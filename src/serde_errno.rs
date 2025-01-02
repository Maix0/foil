pub fn serialize<S>(val: &nix::errno::Errno, ser: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    ser.serialize_i32(*val as _)
}

pub fn deserialize<'de, D>(de: D) -> Result<nix::errno::Errno, D::Error>
where
    D: serde::Deserializer<'de>,
{
    <i32 as serde::Deserialize>::deserialize(de).map(nix::errno::Errno::from_raw)
}
