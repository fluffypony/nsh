#[cfg(test)]
pub(crate) struct EnvVarGuard {
    key: String,
    original: Option<std::ffi::OsString>,
}

#[cfg(test)]
impl EnvVarGuard {
    pub(crate) fn set<K, V>(key: K, value: V) -> Self
    where
        K: Into<String>,
        V: AsRef<std::ffi::OsStr>,
    {
        let key = key.into();
        let original = std::env::var_os(&key);
        // SAFETY: test-only env changes; callers serialize stateful tests where needed.
        unsafe { std::env::set_var(&key, value.as_ref()) };
        Self { key, original }
    }

    pub(crate) fn remove<K: Into<String>>(key: K) -> Self {
        let key = key.into();
        let original = std::env::var_os(&key);
        // SAFETY: test-only env changes; callers serialize stateful tests where needed.
        unsafe { std::env::remove_var(&key) };
        Self { key, original }
    }
}

#[cfg(test)]
impl Drop for EnvVarGuard {
    fn drop(&mut self) {
        if let Some(value) = &self.original {
            // SAFETY: test-only env changes; callers serialize stateful tests where needed.
            unsafe { std::env::set_var(&self.key, value) };
        } else {
            // SAFETY: test-only env changes; callers serialize stateful tests where needed.
            unsafe { std::env::remove_var(&self.key) };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::EnvVarGuard;
    use serial_test::serial;

    const KEY: &str = "NSH_TEST_ENV_VAR_GUARD";

    #[test]
    #[serial]
    fn set_restores_previous_value_on_drop() {
        // SAFETY: test-only env mutation guarded by serial execution.
        unsafe { std::env::set_var(KEY, "original") };

        {
            let _guard = EnvVarGuard::set(KEY, "temporary");
            assert_eq!(std::env::var(KEY).ok().as_deref(), Some("temporary"));
        }

        assert_eq!(std::env::var(KEY).ok().as_deref(), Some("original"));
        // SAFETY: test cleanup guarded by serial execution.
        unsafe { std::env::remove_var(KEY) };
    }

    #[test]
    #[serial]
    fn remove_restores_missing_value_on_drop() {
        // SAFETY: test cleanup guarded by serial execution.
        unsafe { std::env::remove_var(KEY) };

        {
            let _guard = EnvVarGuard::remove(KEY);
            assert_eq!(std::env::var(KEY), Err(std::env::VarError::NotPresent));
        }

        assert_eq!(std::env::var(KEY), Err(std::env::VarError::NotPresent));
    }
}
