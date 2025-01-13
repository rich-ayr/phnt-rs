/// A `cty` implementation that always assumes `target_os = "windows"`.
/// Forked from `::core::ffi`
pub type c_void = ::core::ffi::c_void;

pub type c_char = i8; // Windows specific
pub type c_schar = i8;
pub type c_uchar = u8;
pub type c_short = i16;
pub type c_ushort = u16;

pub type c_int = i32; // Windows specific
pub type c_uint = u32; // Windows specific

pub type c_long = i32; // Windows specific
pub type c_ulong = u32; // Windows specific

pub type c_longlong = i64;
pub type c_ulonglong = u64;

pub type c_float = f32;
pub type c_double = f64;

pub type c_size_t = usize;
pub type c_ssize_t = isize;
pub type c_ptrdiff_t = isize;