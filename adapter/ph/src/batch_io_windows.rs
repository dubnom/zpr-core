pub const AUTO_ENGINE_NAME: &str = "auto";

pub fn engine_names() -> impl Iterator<Item = &'static str> {
    std::iter::empty()
}

pub struct BatchIo;
