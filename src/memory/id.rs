pub use crate::memory::types::generate_id;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn id_generation_works() {
        let id = generate_id("test");
        assert!(id.starts_with("test_"));
    }
}
