extern crate libc;

use libc::c_int;
use libc::funcs::posix88::unistd::getuid;
use std::ffi::CStr;
use std::ffi::CString;
use std::fs;
use std::fs::File;
use std::io::BufRead;
use std::io::BufReader;
use std::io::Result;
use std::path::Path;
use std::path::PathBuf;
use std::ptr;
use std::str;

#[allow(dead_code)]
enum NssStatus {
    TryAgain,
    Unavail,
    NotFound,
    Success,
    Return,
}

impl NssStatus {
    fn to_c(&self) -> c_int {
        match *self {
            NssStatus::TryAgain => -2,
            NssStatus::Unavail => -1,
            NssStatus::NotFound => 0,
            NssStatus::Success => 1,
            NssStatus::Return => 2,
        }
    }
}

#[derive(Debug)]
struct Passwd {
    name: String,
    passwd: String,
    uid: libc::uid_t,
    gid: libc::gid_t,
    gecos: String,
    dir: String,
    shell: String,
}

#[repr(C)]
#[allow(missing_copy_implementations)]
pub struct CPasswd {
    name: *mut libc::c_char,
    passwd: *mut libc::c_char,
    uid: libc::uid_t,
    gid: libc::gid_t,
    gecos: *mut libc::c_char,
    dir: *mut libc::c_char,
    shell: *mut libc::c_char,
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
    buf: BufReader<File>,
}

impl PasswdFile {
    fn new(path: &Path) -> Result<PasswdFile> {
        match File::open(path) {
            Ok(file) => Ok(PasswdFile {
                buf: BufReader::new(file),
            }),
            Err(e) => Err(e),
        }
    }

    fn parse_line(line: String) -> Option<Passwd> {
        let xs = line.split(':').collect::<Vec<&str>>();
        let mut v = xs.iter();

        macro_rules! maybe {
            ($expr: expr) => {{
                match $expr {
                    Some(v) => v,
                    None => return None,
                }
            }};
        }

        Some(Passwd {
            name: maybe!(v.next()).to_string(),
            passwd: maybe!(v.next()).to_string(),
            uid: maybe!(v.next().and_then(|uid| uid.parse::<libc::uid_t>().ok())),
            gid: maybe!(v.next().and_then(|gid| gid.parse::<libc::gid_t>().ok())),
            gecos: maybe!(v.next()).to_string(),
            dir: maybe!(v.next()).to_string(),
            shell: maybe!(v.next()).trim_end().to_string(),
        })
    }
}

impl Iterator for PasswdFile {
    type Item = Passwd;

    fn next(&mut self) -> Option<Passwd> {
        let mut line = String::new();
        self.buf
            .read_line(&mut line)
            .and_then(|_| Ok(PasswdFile::parse_line(line)))
            .unwrap_or(None)
    }
}

struct CBuffer {
    pos: *mut libc::c_char,
    free: libc::size_t,
}

impl CBuffer {
    fn new(ptr: *mut libc::c_char, len: libc::size_t) -> CBuffer {
        CBuffer {
            pos: ptr,
            free: len,
        }
    }

    /* XXX: check free */
    fn write<T>(&mut self, data: *const T, len: usize) -> *mut libc::c_char {
        let t = self.pos;
        unsafe {
            ptr::copy(self.pos, data as *mut i8, len);
            self.pos = self.pos.offset(len as isize);
            self.free -= len as libc::size_t;
        }
        t
    }

    fn write_str(&mut self, string: String) -> *mut libc::c_char {
        let len = string.len();
        let s = CString::new(string).unwrap();
        self.write(s.as_ptr(), len + 1)
    }
}

unsafe fn get_passwd_files() -> Vec<PathBuf> {
    let mut vec = Vec::new();
    match getuid() {
        0 => {
            for de in fs::read_dir("/etc/passwd.d").unwrap() {
                if let Ok(entry) = de {
                    vec.push(entry.path());
                }
            }
        }
        uid => vec.push(PathBuf::from(format!("/etc/passwd.d/{}", uid))),
    }
    vec
}

#[no_mangle]
pub extern "C" fn _nss_multipasswd_setpwent() -> libc::c_int {
    NssStatus::Success.to_c()
}

#[no_mangle]
pub extern "C" fn _nss_multipasswd_endpwent() -> libc::c_int {
    NssStatus::Success.to_c()
}

#[no_mangle]
pub extern "C" fn _nss_multipasswd_getpwent_r() -> libc::c_int {
    NssStatus::Unavail.to_c()
}

#[no_mangle]
pub unsafe extern "C" fn _nss_multipasswd_getpwuid_r(
    uid: libc::uid_t,
    pwbuf: *mut CPasswd,
    buf: *mut libc::c_char,
    buflen: libc::size_t,
    _errnop: *mut libc::c_int,
) -> libc::c_int {
    for path in get_passwd_files() {
        if let Ok(mut file) = PasswdFile::new(path.as_path()) {
            if let Some(entry) = file.find(|entry| entry.uid == uid) {
                entry.to_c_passwd(pwbuf, &mut CBuffer::new(buf, buflen));
                return NssStatus::Success.to_c();
            }
        }
    }
    NssStatus::NotFound.to_c()
}

#[no_mangle]
pub unsafe extern "C" fn _nss_multipasswd_getpwnam_r(
    name_: *const libc::c_char,
    pwbuf: *mut CPasswd,
    buf: *mut libc::c_char,
    buflen: libc::size_t,
    _errnop: *mut libc::c_int,
) -> libc::c_int {
    let s = CStr::from_ptr(name_);
    if let Ok(name) = str::from_utf8(s.to_bytes()) {
        for path in get_passwd_files() {
            if let Ok(mut file) = PasswdFile::new(path.as_path()) {
                if let Some(entry) = file.find(|entry| entry.name == name) {
                    entry.to_c_passwd(pwbuf, &mut CBuffer::new(buf, buflen));
                    return NssStatus::Success.to_c();
                }
            }
        }
    }
    NssStatus::NotFound.to_c()
}
