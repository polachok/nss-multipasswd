#![feature(macro_rules)]
extern crate libc;

use std::ptr;
use std::io::File;
use std::io::fs;
use std::io::BufferedReader;
use std::c_str::CString;
use libc::funcs::posix88::unistd::getuid;

#[allow(dead_code)]
enum NssStatus {
	TryAgain,
	Unavail,
	NotFound,
	Success,
	Return,
}

impl NssStatus {
	fn to_c(&self) -> int {
	match *self {
		NssStatus::TryAgain => -2,
		NssStatus::Unavail  => -1,
		NssStatus::NotFound => 0,
		NssStatus::Success  => 1,
		NssStatus::Return   => 2,
	}
	}
}

#[deriving(Show)]
struct Passwd {
	name: 		String,
	passwd: 	String,
	uid: 		libc::uid_t,
	gid: 		libc::gid_t,
	gecos:		String,
	dir:		String,
	shell: 		String,
}

#[repr(C)]
#[allow(missing_copy_implementations)]
pub struct CPasswd {
	name: 		*mut libc::c_char,
	passwd: 	*mut libc::c_char,
	uid: 		libc::uid_t,
	gid: 		libc::gid_t,
	gecos: 		*mut libc::c_char,
	dir: 		*mut libc::c_char,
	shell: 		*mut libc::c_char,
}

impl Passwd {
	unsafe fn to_c_passwd(self, pwbuf: *mut CPasswd, buf: &mut CBuffer) {
		(*pwbuf).name = buf.write_str(self.name);
		(*pwbuf).passwd = buf.write_str(self.passwd);
		(*pwbuf).uid = self.uid;
		(*pwbuf).gid = self.gid;
		(*pwbuf).gecos = buf.write_str(self.gecos);
		(*pwbuf).dir = buf.write_str(self.dir);
		(*pwbuf).shell = buf.write_str(self.shell);
	}
}

struct PasswdFile {
	buf: BufferedReader<File>,
}

impl PasswdFile {
	fn new(path: &Path) -> Result<PasswdFile, std::io::IoError> {
		match File::open(path) {
			Ok(file) => Ok(PasswdFile { buf: BufferedReader::new(file) }),
			Err(e) => Err(e)
		}
	}

	fn parse_line(line: String) -> Option<Passwd> {
		let xs = line.split(':').collect::<Vec<&str>>();
		let mut v = xs.iter();

		macro_rules! maybe {
			($expr: expr) => ({
				match $expr {
					Some(v) => v,
					None => return None,
				}
			})
		}

		Some(Passwd {
			name: 		maybe!(v.next()).to_string(),
			passwd: 	maybe!(v.next()).to_string(),
			uid: 		maybe!(v.next().and_then(|uid| from_str::<libc::uid_t>(*uid))),
			gid: 		maybe!(v.next().and_then(|gid| from_str::<libc::uid_t>(*gid))),
			gecos:		maybe!(v.next()).to_string(),
			dir: 		maybe!(v.next()).to_string(),
			shell: 		maybe!(v.next()).trim_right().to_string(),
		})
	}
}

impl Iterator<Passwd> for PasswdFile {
	fn next(&mut self) -> Option<Passwd> {
		self.buf.lines()
				.next()
				.and_then(|r| r.and_then(|line| Ok(PasswdFile::parse_line(line))).unwrap_or(None))
	}
}

struct CBuffer {
	pos: *mut libc::c_char,
	free: libc::size_t,
}

impl CBuffer {
	fn new(ptr: *mut libc::c_char, len: libc::size_t) -> CBuffer {
		CBuffer { pos: ptr, free: len }
	}

	/* XXX: check free */
	fn write<T>(&mut self, data: *const T, len: uint) -> *mut libc::c_char {
		let t = self.pos;
		unsafe {
			ptr::copy_memory(self.pos, data as *const i8 , len);
			self.pos = self.pos.offset(len as int);
			self.free -= len as libc::size_t;
		}
		t
	}

	fn write_str<S: ToCStr>(&mut self, string: S) -> *mut libc::c_char {
		let s = string.to_c_str();
		self.write(s.as_ptr(), s.len() + 1)
	}
}

unsafe fn get_passwd_files() -> Vec<Path> {
	match getuid() {
		0   => fs::readdir(&Path::new("/etc/passwd.d")).unwrap_or(Vec::new()),
		uid => vec![Path::new(format!("/etc/passwd.d/{}", uid))],
	}
}

#[no_mangle]
pub extern fn _nss_multipasswd_setpwent() -> int { NssStatus::Success.to_c() }

#[no_mangle]
pub extern fn _nss_multipasswd_endpwent() -> int { NssStatus::Success.to_c() }

#[no_mangle]
pub extern fn _nss_multipasswd_getpwent_r() -> int { NssStatus::Unavail.to_c() }

#[no_mangle]
pub unsafe extern "C" fn _nss_multipasswd_getpwuid_r(uid: libc::uid_t, pwbuf: *mut CPasswd, buf: *mut libc::c_char,
	buflen: libc::size_t, errnop: *mut int) -> int {
	for path in get_passwd_files().iter() {
		if let Ok(mut file) = PasswdFile::new(path) {
			if let Some(entry) = file.find(|entry| entry.uid == uid) {
				entry.to_c_passwd(pwbuf, &mut CBuffer::new(buf, buflen));
				return NssStatus::Success.to_c();
			}
		}
	}
	NssStatus::NotFound.to_c()
}

#[no_mangle]
pub unsafe extern "C" fn _nss_multipasswd_getpwnam_r(name_: *const libc::c_char, pwbuf: *mut CPasswd,
	buf: *mut libc::c_char, buflen: libc::size_t, errnop: *mut int) -> int {
	if let Some(name) = CString::new(name_, false).as_str() {
		for path in get_passwd_files().iter() {
			if let Ok(mut file) = PasswdFile::new(path) {
				if let Some(entry) = file.find(|entry| entry.name == name) {
					entry.to_c_passwd(pwbuf, &mut CBuffer::new(buf, buflen));
					return NssStatus::Success.to_c();
				}
			}
		}
	}
	NssStatus::NotFound.to_c()
}
