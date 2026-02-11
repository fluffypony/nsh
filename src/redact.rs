//! Secret redaction engine for nsh.
//!
//! Built-in secret patterns are derived from Amp's secret detection system.
//! Used with permission from Amp Inc. Copyright © Amp Inc. (https://ampcode.com)
//! Pattern definitions may be updated periodically to match upstream changes.

use std::sync::LazyLock;

use crate::config::RedactionConfig;

struct SecretPattern {
    id: &'static str,
    pattern: &'static str,
    keywords: &'static [&'static str],
    case_insensitive: bool,
}

struct CompiledSecretPattern {
    id: &'static str,
    regex: regex::Regex,
    keywords: &'static [&'static str],
    case_insensitive: bool,
}

const BUILTIN_PATTERNS: &[SecretPattern] = &[
    // Sourcegraph
    SecretPattern {
        id: "sourcegraph-access-token-v3",
        pattern: r"(sgp_(?:[a-fA-F0-9]{16}|local)_[a-fA-F0-9]{40})",
        keywords: &["sgp_"],
        case_insensitive: false,
    },
    SecretPattern {
        id: "sourcegraph-access-token-v2",
        pattern: r"(sgp_[a-fA-F0-9]{40})",
        keywords: &["sgp_"],
        case_insensitive: false,
    },
    SecretPattern {
        id: "sourcegraph-dotcom-user-gateway",
        pattern: r"(sgd_[a-fA-F0-9]{64})",
        keywords: &["sgd_"],
        case_insensitive: false,
    },
    SecretPattern {
        id: "sourcegraph-license-key",
        pattern: r"(slk_[a-fA-F0-9]{64})",
        keywords: &["slk_"],
        case_insensitive: false,
    },
    SecretPattern {
        id: "sourcegraph-enterprise-subscription",
        pattern: r"(sgs_[a-fA-F0-9]{64})",
        keywords: &["sgs_"],
        case_insensitive: false,
    },
    SecretPattern {
        id: "sourcegraph-amp",
        pattern: r"(sgamp_user_[A-Z0-9]{26}_[a-f0-9]{64})",
        keywords: &["sgamp_user_"],
        case_insensitive: false,
    },
    SecretPattern {
        id: "sourcegraph-amp-auth-bypass",
        pattern: r"(sgamp_user_auth-bypass_[a-zA-Z0-9_-]+)",
        keywords: &["sgamp_user_auth-bypass_"],
        case_insensitive: false,
    },
    SecretPattern {
        id: "sourcegraph-workspace-token",
        pattern: r"(sgp_ws[a-fA-F0-9]{32}_[a-fA-F0-9]{40})",
        keywords: &["sgp_ws"],
        case_insensitive: false,
    },
    // GitHub
    SecretPattern {
        id: "github-pat",
        pattern: r"(ghp_[0-9a-zA-Z]{36})",
        keywords: &["ghp_"],
        case_insensitive: false,
    },
    SecretPattern {
        id: "github-oauth",
        pattern: r"(gho_[0-9a-zA-Z]{36})",
        keywords: &["gho_"],
        case_insensitive: false,
    },
    SecretPattern {
        id: "github-app-token",
        pattern: r"((ghu|ghs)_[0-9a-zA-Z]{36})",
        keywords: &["ghu_", "ghs_"],
        case_insensitive: false,
    },
    SecretPattern {
        id: "github-refresh-token",
        pattern: r"(ghr_[0-9a-zA-Z]{76})",
        keywords: &["ghr_"],
        case_insensitive: false,
    },
    SecretPattern {
        id: "github-fine-grained-pat",
        pattern: r"(github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59})",
        keywords: &["github_pat_"],
        case_insensitive: false,
    },
    // GitLab
    SecretPattern {
        id: "gitlab-pat",
        pattern: r"(glpat-[0-9a-zA-Z_-]{20})",
        keywords: &["glpat-"],
        case_insensitive: false,
    },
    // AWS
    SecretPattern {
        id: "aws-access-key-id",
        pattern: r"((A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16})",
        keywords: &[
            "AKIA", "AGPA", "AIDA", "AROA", "AIPA", "ANPA", "ANVA", "ASIA",
        ],
        case_insensitive: false,
    },
    SecretPattern {
        id: "aws-secret-access-key",
        pattern: r"(?i)(aws[_-]secret[_-]access[_-]key[_-][A-Za-z0-9/+=]{40})",
        keywords: &["key"],
        case_insensitive: true,
    },
    // Hugging Face
    SecretPattern {
        id: "hugging-face-access-token",
        pattern: r"(hf_[A-Za-z0-9]{34,40})",
        keywords: &["hf_"],
        case_insensitive: false,
    },
    // Asymmetric Private Key
    SecretPattern {
        id: "private-key",
        pattern: r"(?i)-----\s*?BEGIN[ A-Z0-9_-]*?PRIVATE KEY(?: BLOCK)?\s*?-----\s*([A-Za-z0-9=+/\s]+)\s*-----\s*?END[ A-Z0-9_-]*? PRIVATE KEY(?: BLOCK)?\s*?-----",
        keywords: &["-----"],
        case_insensitive: true,
    },
    // Shopify
    SecretPattern {
        id: "shopify-token",
        pattern: r"(shp(ss|at|ca|pa)_[a-fA-F0-9]{32})",
        keywords: &["shpss_", "shpat_", "shpca_", "shppa_"],
        case_insensitive: false,
    },
    // Slack
    SecretPattern {
        id: "slack-access-token",
        pattern: r"((xox[baoprs]-|xapp-|xwfp-)([0-9a-zA-Z-]{10,100}))",
        keywords: &[
            "xoxb-", "xoxa-", "xoxp-", "xoxr-", "xoxs-", "xoxo-", "xapp-", "xwfp-",
        ],
        case_insensitive: false,
    },
    SecretPattern {
        id: "slack-config-refresh-token",
        pattern: r"(?i)(xoxe-\d-[a-zA-Z0-9]{146})",
        keywords: &["xoxe-"],
        case_insensitive: true,
    },
    SecretPattern {
        id: "slack-config-access-token",
        pattern: r"(?i)(xoxe.xox[bp]-\d-[A-Z0-9]{163,166})",
        keywords: &["xoxe.xoxb-", "xoxe.xoxp-"],
        case_insensitive: true,
    },
    SecretPattern {
        id: "slack-web-hook",
        pattern: r"(?i)(https://hooks\.slack\.com/(services|triggers|workflows)/[A-Za-z0-9+/]{43,56})",
        keywords: &["hooks.slack.com"],
        case_insensitive: true,
    },
    // Stripe
    SecretPattern {
        id: "stripe-secret-token",
        pattern: r"(?i)(sk_(test|live)_[0-9a-z]{10,99})",
        keywords: &["sk_test_", "sk_live_"],
        case_insensitive: true,
    },
    // Supabase
    SecretPattern {
        id: "supabase-service-key",
        pattern: r"(sbp_[a-fA-F0-9]{40})",
        keywords: &["sbp_"],
        case_insensitive: false,
    },
    // PyPI
    SecretPattern {
        id: "pypi-upload-token",
        pattern: r"(pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,1000})",
        keywords: &["pypi-AgEIcHlwaS5vcmc"],
        case_insensitive: false,
    },
    // Heroku
    SecretPattern {
        id: "heroku-api-key",
        pattern: r#"(?i)(?:heroku[a-z0-9_ .,-]{0,25})(?:=|>|:=|\|\|:|<=|=>|:).{0,5}['"](\d[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12})['"]"#,
        keywords: &["heroku"],
        case_insensitive: true,
    },
    // Twilio
    SecretPattern {
        id: "twilio-api-key",
        pattern: r"(SK[0-9a-fA-F]{32})",
        keywords: &["SK"],
        case_insensitive: false,
    },
    // Age
    SecretPattern {
        id: "age-secret-key",
        pattern: r"(AGE-SECRET-KEY-1[QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L]{58})",
        keywords: &["AGE-SECRET-KEY-1"],
        case_insensitive: false,
    },
    // JWT
    SecretPattern {
        id: "jwt-token",
        pattern: r"(ey[a-zA-Z0-9]{17,}\.ey[a-zA-Z0-9/\\_-]{17,}\.(?:[a-zA-Z0-9/\\_-]{10,}={0,2})?)",
        keywords: &[".eyJ"],
        case_insensitive: false,
    },
    // npm
    SecretPattern {
        id: "npm-access-token",
        pattern: r"(?i)(npm_[a-z0-9]{36})",
        keywords: &["npm_"],
        case_insensitive: true,
    },
    // SendGrid
    SecretPattern {
        id: "sendgrid-api-token",
        pattern: r"(?i)(SG\.[a-z0-9_.-]{66})",
        keywords: &["SG."],
        case_insensitive: true,
    },
    // Docker
    SecretPattern {
        id: "dockerconfig-secret",
        pattern: r"(?i)((\.dockerconfigjson|dockercfg):\s*\|*\s*((ey|ew)+[A-Za-z0-9/+=]+))",
        keywords: &["dockerc"],
        case_insensitive: true,
    },
    // Linear
    SecretPattern {
        id: "linear-api-token",
        pattern: r"(?i)(lin_api_[a-z0-9]{40})",
        keywords: &["lin_api_"],
        case_insensitive: true,
    },
    // Sendinblue
    SecretPattern {
        id: "sendinblue-api-token",
        pattern: r"(?i)(xkeysib-[a-f0-9]{64}-[a-z0-9]{16})",
        keywords: &["xkeysib-"],
        case_insensitive: true,
    },
    // PlanetScale
    SecretPattern {
        id: "planetscale-api-token",
        pattern: r"(?i)(pscale_tkn_[a-z0-9_.-]{43})",
        keywords: &["pscale_tkn_"],
        case_insensitive: true,
    },
    SecretPattern {
        id: "planetscale-password",
        pattern: r"(?i)(pscale_pw_[a-z0-9_.-]{43})",
        keywords: &["pscale_pw_"],
        case_insensitive: true,
    },
    // Doppler
    SecretPattern {
        id: "doppler-api-token",
        pattern: r"(?i)(dp\.pt\.[a-z0-9]{43})",
        keywords: &["dp.pt."],
        case_insensitive: true,
    },
    // Discord
    SecretPattern {
        id: "discord-api-token",
        pattern: r#"(?i)(?:discord[a-z0-9_ .,-]{0,25})(?:=|>|:=|\|\|:|<=|=>|:).{0,5}['"]([a-h0-9]{64})['"]"#,
        keywords: &["discord"],
        case_insensitive: true,
    },
    SecretPattern {
        id: "discord-client-id",
        pattern: r#"(?i)(?:discord[a-z0-9_ .,-]{0,25})(?:=|>|:=|\|\|:|<=|=>|:).{0,5}['"]([0-9]{18})['"]"#,
        keywords: &["discord"],
        case_insensitive: true,
    },
    SecretPattern {
        id: "discord-client-secret",
        pattern: r#"(?i)(?:discord[a-z0-9_ .,-]{0,25})(?:=|>|:=|\|\|:|<=|=>|:).{0,5}['"]([a-z0-9=_-]{32})['"]"#,
        keywords: &["discord"],
        case_insensitive: true,
    },
    // Pulumi
    SecretPattern {
        id: "pulumi-api-token",
        pattern: r"(pul-[a-f0-9]{40})",
        keywords: &["pul-"],
        case_insensitive: false,
    },
    // Postman
    SecretPattern {
        id: "postman-api-token",
        pattern: r"(?i)(PMAK-[a-f0-9]{24}-[a-f0-9]{34})",
        keywords: &["PMAK-"],
        case_insensitive: true,
    },
    // Facebook
    SecretPattern {
        id: "facebook-token",
        pattern: r#"(?i)(?:facebook[a-z0-9_ .,-]{0,25})(?:=|>|:=|\|\|:|<=|=>|:).{0,5}['"]([a-f0-9]{32})['"]"#,
        keywords: &["facebook"],
        case_insensitive: true,
    },
    // Twitter
    SecretPattern {
        id: "twitter-token",
        pattern: r#"(?i)(?:twitter[a-z0-9_ .,-]{0,25})(?:=|>|:=|\|\|:|<=|=>|:).{0,5}['"]([a-f0-9]{35,44})['"]"#,
        keywords: &["twitter"],
        case_insensitive: true,
    },
    // Adobe
    SecretPattern {
        id: "adobe-client-id",
        pattern: r#"(?i)(?:adobe[a-z0-9_ .,-]{0,25})(?:=|>|:=|\|\|:|<=|=>|:).{0,5}['"]([a-f0-9]{32})['"]"#,
        keywords: &["adobe"],
        case_insensitive: true,
    },
    SecretPattern {
        id: "adobe-client-secret",
        pattern: r"(?i)(p8e-[a-z0-9]{32})",
        keywords: &["p8e-"],
        case_insensitive: true,
    },
    // Alibaba
    SecretPattern {
        id: "alibaba-access-key-id",
        pattern: r"(?i)((LTAI)[a-z0-9]{20})",
        keywords: &["LTAI"],
        case_insensitive: true,
    },
    SecretPattern {
        id: "alibaba-secret-key",
        pattern: r#"(?i)(?:alibaba[a-z0-9_ .,-]{0,25})(?:=|>|:=|\|\|:|<=|=>|:).{0,5}['"]([a-z0-9]{30})['"]"#,
        keywords: &["alibaba"],
        case_insensitive: true,
    },
    // Asana
    SecretPattern {
        id: "asana-client-id",
        pattern: r#"(?i)(?:asana[a-z0-9_ .,-]{0,25})(?:=|>|:=|\|\|:|<=|=>|:).{0,5}['"]([0-9]{16})['"]"#,
        keywords: &["asana"],
        case_insensitive: true,
    },
    SecretPattern {
        id: "asana-client-secret",
        pattern: r#"(?i)(?:asana[a-z0-9_ .,-]{0,25})(?:=|>|:=|\|\|:|<=|=>|:).{0,5}['"]([a-z0-9]{32})['"]"#,
        keywords: &["asana"],
        case_insensitive: true,
    },
    // Atlassian
    SecretPattern {
        id: "atlassian-api-token",
        pattern: r#"(?i)(?:atlassian[a-z0-9_ .,-]{0,25})(?:=|>|:=|\|\|:|<=|=>|:).{0,5}['"]([a-z0-9]{24})['"]"#,
        keywords: &["atlassian"],
        case_insensitive: true,
    },
    // Beamer
    SecretPattern {
        id: "beamer-api-token",
        pattern: r#"(?i)(?:beamer[a-z0-9_ .,-]{0,25})(?:=|>|:=|\|\|:|<=|=>|:).{0,5}['"](b_[a-z0-9=_-]{44})['"]"#,
        keywords: &["beamer"],
        case_insensitive: true,
    },
    // Buildkite
    SecretPattern {
        id: "buildkite-agent-token",
        pattern: r"(bkua_[a-fA-F0-9]{40})",
        keywords: &["bkua_"],
        case_insensitive: false,
    },
    // Clojars
    SecretPattern {
        id: "clojars-api-token",
        pattern: r"(?i)(CLOJARS_[a-z0-9]{60})",
        keywords: &["CLOJARS_"],
        case_insensitive: true,
    },
    // Contentful
    SecretPattern {
        id: "contentful-delivery-api-token",
        pattern: r#"(?i)(?:contentful[a-z0-9_ .,-]{0,25})(?:=|>|:=|\|\|:|<=|=>|:).{0,5}['"]([a-z0-9=_-]{43})['"]"#,
        keywords: &["contentful"],
        case_insensitive: true,
    },
    // Databricks
    SecretPattern {
        id: "databricks-api-token",
        pattern: r"(dapi[a-h0-9]{32})",
        keywords: &["dapi"],
        case_insensitive: false,
    },
    // Dropbox
    SecretPattern {
        id: "dropbox-api-secret",
        pattern: r#"(?i)(?:dropbox[a-z0-9_ .,-]{0,25})(?:=|>|:=|\|\|:|<=|=>|:).{0,5}['"]([a-z0-9]{15})['"]"#,
        keywords: &["dropbox"],
        case_insensitive: true,
    },
    SecretPattern {
        id: "dropbox-short-lived-api-token",
        pattern: r#"(?i)(?:dropbox[a-z0-9_ .,-]{0,25})(?:=|>|:=|\|\|:|<=|=>|:).{0,5}['"](sl\.[a-z0-9=_-]{135})['"]"#,
        keywords: &["dropbox"],
        case_insensitive: true,
    },
    SecretPattern {
        id: "dropbox-long-lived-api-token",
        pattern: r#"(?i)(?:dropbox[a-z0-9_ .,-]{0,25})(?:=|>|:=|\|\|:|<=|=>|:).{0,5}['"]([a-z0-9]{11}(AAAAAAAAAA)[a-z0-9_=-]{43})['"]"#,
        keywords: &["dropbox"],
        case_insensitive: true,
    },
    // Duffel
    SecretPattern {
        id: "duffel-api-token",
        pattern: r"(?i)(duffel_(test|live)_[a-z0-9_-]{43})",
        keywords: &["duffel_test_", "duffel_live_"],
        case_insensitive: true,
    },
    // Dynatrace
    SecretPattern {
        id: "dynatrace-api-token",
        pattern: r"(?i)(dt0c01\.[a-z0-9]{24}\.[a-z0-9]{64})",
        keywords: &["dt0c01."],
        case_insensitive: true,
    },
    // EasyPost
    SecretPattern {
        id: "easypost-api-token",
        pattern: r"(?i)(EZ[AT]K[a-z0-9]{54})",
        keywords: &["EZAK", "EZAT"],
        case_insensitive: true,
    },
    // Fastly
    SecretPattern {
        id: "fastly-api-token",
        pattern: r#"(?i)(?:fastly[a-z0-9_ .,-]{0,25})(?:=|>|:=|\|\|:|<=|=>|:).{0,5}['"]([a-z0-9=_-]{32})['"]"#,
        keywords: &["fastly"],
        case_insensitive: true,
    },
    // Finicity
    SecretPattern {
        id: "finicity-client-secret",
        pattern: r#"(?i)(?:finicity[a-z0-9_ .,-]{0,25})(?:=|>|:=|\|\|:|<=|=>|:).{0,5}['"]([a-z0-9]{20})['"]"#,
        keywords: &["finicity"],
        case_insensitive: true,
    },
    SecretPattern {
        id: "finicity-api-token",
        pattern: r#"(?i)(?:finicity[a-z0-9_ .,-]{0,25})(?:=|>|:=|\|\|:|<=|=>|:).{0,5}['"]([a-f0-9]{32})['"]"#,
        keywords: &["finicity"],
        case_insensitive: true,
    },
    // Flutterwave
    SecretPattern {
        id: "flutterwave-public-key",
        pattern: r"(?i)(FLW(PUB|SEC)K_TEST-[a-h0-9]{32}-X)",
        keywords: &["FLWSECK_TEST-", "FLWPUBK_TEST-"],
        case_insensitive: true,
    },
    SecretPattern {
        id: "flutterwave-enc-key",
        pattern: r"(FLWSECK_TEST[a-h0-9]{12})",
        keywords: &["FLWSECK_TEST"],
        case_insensitive: false,
    },
    // Frame.io
    SecretPattern {
        id: "frameio-api-token",
        pattern: r"(?i)(fio-u-[a-z0-9_=-]{64})",
        keywords: &["fio-u-"],
        case_insensitive: true,
    },
    // GoCardless
    SecretPattern {
        id: "gocardless-api-token",
        pattern: r"(?i)(live_[a-z0-9_=-]{40})",
        keywords: &["live_"],
        case_insensitive: true,
    },
    // Grafana
    SecretPattern {
        id: "grafana-api-token",
        pattern: r"(?i)(eyJrIjoi[a-z0-9_=-]{72,92})",
        keywords: &["eyJrIjoi"],
        case_insensitive: true,
    },
    // HashiCorp
    SecretPattern {
        id: "hashicorp-tf-api-token",
        pattern: r"(?i)([a-z0-9]{14}\.atlasv1\.[a-z0-9_=-]{60,70})",
        keywords: &["atlasv1."],
        case_insensitive: true,
    },
    // HubSpot
    SecretPattern {
        id: "hubspot-api-token",
        pattern: r#"(?i)(?:hubspot[a-z0-9_ .,-]{0,25})(?:=|>|:=|\|\|:|<=|=>|:).{0,5}['"]([a-h0-9]{8}-[a-h0-9]{4}-[a-h0-9]{4}-[a-h0-9]{4}-[a-h0-9]{12})['"]"#,
        keywords: &["hubspot"],
        case_insensitive: true,
    },
    // Intercom
    SecretPattern {
        id: "intercom-api-token",
        pattern: r#"(?i)(?:intercom[a-z0-9_ .,-]{0,25})(?:=|>|:=|\|\|:|<=|=>|:).{0,5}['"]([a-z0-9=_]{60})['"]"#,
        keywords: &["intercom"],
        case_insensitive: true,
    },
    SecretPattern {
        id: "intercom-client-secret",
        pattern: r#"(?i)(?:intercom[a-z0-9_ .,-]{0,25})(?:=|>|:=|\|\|:|<=|=>|:).{0,5}['"]([a-h0-9]{8}-[a-h0-9]{4}-[a-h0-9]{4}-[a-h0-9]{4}-[a-h0-9]{12})['"]"#,
        keywords: &["intercom"],
        case_insensitive: true,
    },
    // Ionic
    SecretPattern {
        id: "ionic-api-token",
        pattern: r#"(?i)(?:ionic[a-z0-9_ .,-]{0,25})(?:=|>|:=|\|\|:|<=|=>|:).{0,5}['"](ion_[a-z0-9]{42})['"]"#,
        keywords: &["ionic"],
        case_insensitive: true,
    },
    // Linear (client secret)
    SecretPattern {
        id: "linear-client-secret",
        pattern: r#"(?i)(?:linear[a-z0-9_ .,-]{0,25})(?:=|>|:=|\|\|:|<=|=>|:).{0,5}['"]([a-f0-9]{32})['"]"#,
        keywords: &["linear"],
        case_insensitive: true,
    },
    // Lob
    SecretPattern {
        id: "lob-api-key",
        pattern: r#"(?i)(?:lob[a-z0-9_ .,-]{0,25})(?:=|>|:=|\|\|:|<=|=>|:).{0,5}['"]((live|test)_[a-f0-9]{35})['"]"#,
        keywords: &["lob"],
        case_insensitive: true,
    },
    // Mailchimp
    SecretPattern {
        id: "mailchimp-api-key",
        pattern: r#"(?i)(?:mailchimp[a-z0-9_ .,-]{0,25})(?:=|>|:=|\|\|:|<=|=>|:).{0,5}['"]([a-f0-9]{32}-us20)['"]"#,
        keywords: &["mailchimp"],
        case_insensitive: true,
    },
    // Mailgun
    SecretPattern {
        id: "mailgun-token",
        pattern: r#"(?i)(?:mailgun[a-z0-9_ .,-]{0,25})(?:=|>|:=|\|\|:|<=|=>|:).{0,5}['"]((pub)?key-[a-f0-9]{32})['"]"#,
        keywords: &["mailgun"],
        case_insensitive: true,
    },
    SecretPattern {
        id: "mailgun-signing-key",
        pattern: r#"(?i)(?:mailgun[a-z0-9_ .,-]{0,25})(?:=|>|:=|\|\|:|<=|=>|:).{0,5}['"]([a-h0-9]{32}-[a-h0-9]{8}-[a-h0-9]{8})['"]"#,
        keywords: &["mailgun"],
        case_insensitive: true,
    },
    // Mapbox
    SecretPattern {
        id: "mapbox-api-token",
        pattern: r"(?i)(pk\.[a-z0-9]{60}\.[a-z0-9]{22})",
        keywords: &["pk."],
        case_insensitive: true,
    },
    // MessageBird
    SecretPattern {
        id: "messagebird-api-token",
        pattern: r#"(?i)(?:messagebird[a-z0-9_ .,-]{0,25})(?:=|>|:=|\|\|:|<=|=>|:).{0,5}['"]([a-z0-9]{25})['"]"#,
        keywords: &["messagebird"],
        case_insensitive: true,
    },
    SecretPattern {
        id: "messagebird-client-id",
        pattern: r#"(?i)(?:messagebird[a-z0-9_ .,-]{0,25})(?:=|>|:=|\|\|:|<=|=>|:).{0,5}['"]([a-h0-9]{8}-[a-h0-9]{4}-[a-h0-9]{4}-[a-h0-9]{4}-[a-h0-9]{12})['"]"#,
        keywords: &["messagebird"],
        case_insensitive: true,
    },
    // New Relic
    SecretPattern {
        id: "new-relic-user-api-key",
        pattern: r"(NRAK-[A-Z0-9]{27})",
        keywords: &["NRAK-"],
        case_insensitive: false,
    },
    SecretPattern {
        id: "new-relic-user-api-id",
        pattern: r#"(?i)(?:newrelic[a-z0-9_ .,-]{0,25})(?:=|>|:=|\|\|:|<=|=>|:).{0,5}['"]([A-Z0-9]{64})['"]"#,
        keywords: &["newrelic"],
        case_insensitive: true,
    },
    SecretPattern {
        id: "new-relic-browser-api-token",
        pattern: r"(NRJS-[a-f0-9]{19})",
        keywords: &["NRJS-"],
        case_insensitive: false,
    },
    // Private Packagist
    SecretPattern {
        id: "private-packagist-token",
        pattern: r"(?i)(packagist_[ou][ru]t_[a-f0-9]{68})",
        keywords: &["packagist_uut_", "packagist_ort_", "packagist_out_"],
        case_insensitive: true,
    },
    // RubyGems
    SecretPattern {
        id: "rubygems-api-token",
        pattern: r"(rubygems_[a-f0-9]{48})",
        keywords: &["rubygems_"],
        case_insensitive: false,
    },
    // Shippo
    SecretPattern {
        id: "shippo-api-token",
        pattern: r"(shippo_(live|test)_[a-f0-9]{40})",
        keywords: &["shippo_live_", "shippo_test_"],
        case_insensitive: false,
    },
    // LinkedIn
    SecretPattern {
        id: "linkedin-client-secret",
        pattern: r#"(?i)(?:linkedin[a-z0-9_ .,-]{0,25})(?:=|>|:=|\|\|:|<=|=>|:).{0,5}['"]([a-z]{16})['"]"#,
        keywords: &["linkedin"],
        case_insensitive: true,
    },
    SecretPattern {
        id: "linkedin-client-id",
        pattern: r#"(?i)(?:linkedin[a-z0-9_ .,-]{0,25})(?:=|>|:=|\|\|:|<=|=>|:).{0,5}['"]([a-z0-9]{14})['"]"#,
        keywords: &["linkedin"],
        case_insensitive: true,
    },
    // Twitch
    SecretPattern {
        id: "twitch-api-token",
        pattern: r#"(?i)(?:twitch[a-z0-9_ .,-]{0,25})(?:=|>|:=|\|\|:|<=|=>|:).{0,5}['"]([a-z0-9]{30})['"]"#,
        keywords: &["twitch"],
        case_insensitive: true,
    },
    // Typeform
    SecretPattern {
        id: "typeform-api-token",
        pattern: r"(?i)(?:typeform[a-z0-9_ .,-]{0,25})(?:=|>|:=|\|\|:|<=|=>|:).{0,5}(tfp_[a-z0-9_.=-]{59})",
        keywords: &["typeform"],
        case_insensitive: true,
    },
    // Todoist
    SecretPattern {
        id: "todoist-api-token",
        pattern: r#"(?i)(?:todoist[a-z0-9_ .,-]{0,25})(?:=|>|:=|\|\|:|<=|=>|:)[\s'"]{0,3}([0-9a-f]{40})"#,
        keywords: &["todoist"],
        case_insensitive: true,
    },
    // OpenAI
    SecretPattern {
        id: "openai-api-key",
        pattern: r"(sk-[a-zA-Z0-9]{50})",
        keywords: &["sk-"],
        case_insensitive: false,
    },
    SecretPattern {
        id: "openai-api-key-project",
        pattern: r"(?i)(sk-proj-[A-Za-z0-9]{24}-[A-Za-z0-9]{40,128})",
        keywords: &["sk-proj-"],
        case_insensitive: true,
    },
    SecretPattern {
        id: "openai-api-key-env",
        pattern: r"(?i)(sk-(?:live|test)-[A-Za-z0-9]{24}-[A-Za-z0-9]{40,128})",
        keywords: &["sk-live-", "sk-test-"],
        case_insensitive: true,
    },
    // Anthropic
    SecretPattern {
        id: "anthropic-api-key",
        pattern: r"(sk-ant-([a-zA-Z0-9]{1,10}-)?[a-zA-Z0-9_-]{32,128})",
        keywords: &["sk-ant-"],
        case_insensitive: false,
    },
    // Canva
    SecretPattern {
        id: "canva-token",
        pattern: r"\b(cnv[a-z0-9]{2}[A-Za-z0-9_=-]+[a-f0-9]{8})\b",
        keywords: &["cnv"],
        case_insensitive: false,
    },
    // Generic patterns
    SecretPattern {
        id: "api-key",
        pattern: r#"(?i)(?:[a-z0-9_ .,-]{0,25}api[-_](?:key|token)(?!length|count|max|min|maxlength|_length|_count|_min|_maxlength)[a-z0-9_ .,-]{0,25})\s*(?:=|>|:=|\|\|:|<=|=>|:)\s*['"]?((?!.*(?:api|key|secret|foo|example|dummy|password|12345|abcde|placeholder|fake|token))[a-z0-9+/_-]{6,128})['"]?(?=\s|$|[;,\]})'"])"#,
        keywords: &["api-key", "api_key", "api-token", "api_token"],
        case_insensitive: true,
    },
    SecretPattern {
        id: "webhook-secret",
        pattern: r#"(?i)(?:[a-z0-9_ .,-]{0,25}webhook[-_]secret(?!length|count|max|min|maxlength|_length|_count|_min|_maxlength)[a-z0-9_ .,-]{0,25})\s*(?:=|>|:=|\|\|:|<=|=>|:)\s*['"]?((?!.*(?:api|key|secret|foo|example|dummy|password|12345|abcde|placeholder|fake|token|webhook))[a-z0-9+/=_-]{6,128})['"]?(?=\s|$|[;,\]})'"])"#,
        keywords: &["webhook-secret", "webhook_secret"],
        case_insensitive: true,
    },
    SecretPattern {
        id: "password",
        pattern: r#"(?i)(?:[a-z0-9_ .,-]{0,25}password(?!length|count|max|min|maxlength|_length|_count|_min|_maxlength)[a-z0-9_ .,-]{0,25})\s*(?:=|>|:=|\|\|:|<=|=>|:)\s*['"]?((?!.*(?:api|key|secret|foo|example|dummy|password|12345|abcde|placeholder|fake|token|password|pass|pwd))[a-z0-9+/=_-]{6,128})['"]?(?=\s|$|[;,\]})'"])"#,
        keywords: &["password"],
        case_insensitive: true,
    },
    SecretPattern {
        id: "sk-secret",
        pattern: r#"(?i)(?:^|['"\s])(sk(?:[-_][a-z0-9]{1,10})?[-_][a-z0-9]{10,99})(?:$|['"\s])"#,
        keywords: &["sk-", "sk_"],
        case_insensitive: true,
    },
];

static COMPILED_BUILTINS: LazyLock<Vec<CompiledSecretPattern>> = LazyLock::new(|| {
    BUILTIN_PATTERNS
        .iter()
        .filter_map(|p| {
            let flags = if p.case_insensitive { "(?i)" } else { "" };
            let full_pattern = if p.pattern.starts_with("(?i)") {
                p.pattern.to_string()
            } else {
                format!("{}{}", flags, p.pattern)
            };
            match regex::Regex::new(&full_pattern) {
                Ok(regex) => Some(CompiledSecretPattern {
                    id: p.id,
                    regex,
                    keywords: p.keywords,
                    case_insensitive: p.case_insensitive,
                }),
                Err(e) => {
                    tracing::warn!("Failed to compile secret pattern '{}': {e}", p.id);
                    None
                }
            }
        })
        .collect()
});

fn compiled_builtins() -> &'static [CompiledSecretPattern] {
    &COMPILED_BUILTINS
}

fn strip_invisible_unicode(input: &str) -> String {
    input
        .chars()
        .filter(|&c| {
            !('\u{E0000}'..='\u{E007F}').contains(&c)
                && c != '\u{200B}'
                && c != '\u{200C}'
                && c != '\u{200D}'
                && c != '\u{FEFF}'
                && c != '\u{00AD}'
        })
        .collect()
}

pub fn redact_secrets(text: &str, config: &RedactionConfig) -> String {
    if !config.enabled {
        return text.to_string();
    }

    let mut result = strip_invisible_unicode(text);

    if !config.disable_builtin {
        for pat in compiled_builtins() {
            let text_check = if pat.case_insensitive {
                result.to_lowercase()
            } else {
                result.clone()
            };
            let has_keyword = pat.keywords.iter().any(|kw| {
                if pat.case_insensitive {
                    text_check.contains(&kw.to_lowercase())
                } else {
                    text_check.contains(kw)
                }
            });
            if !has_keyword {
                continue;
            }
            result = pat
                .regex
                .replace_all(&result, |caps: &regex::Captures| {
                    if let Some(m) = caps.get(1) {
                        let full = caps.get(0).unwrap().as_str();
                        full.replace(m.as_str(), &format!("[REDACTED:{}]", pat.id))
                    } else {
                        format!("[REDACTED:{}]", pat.id)
                    }
                })
                .to_string();
        }
    }

    for user_pattern in &config.patterns {
        if let Ok(re) = regex::Regex::new(user_pattern) {
            result = re
                .replace_all(&result, config.replacement.as_str())
                .to_string();
        }
    }

    result
}

#[allow(dead_code)]
const SENSITIVE_URL_PARAMS: &[&str] = &[
    "token",
    "key",
    "api_key",
    "apikey",
    "access_token",
    "secret",
    "password",
    "auth",
    "authorization",
    "bearer",
    "jwt",
    "session",
    "sessionid",
    "sid",
];

#[allow(dead_code)]
pub fn redact_url(url: &str) -> String {
    if let Some(qmark) = url.find('?') {
        let (base, query) = url.split_at(qmark);
        let query = &query[1..]; // skip '?'
        let mut parts: Vec<String> = Vec::new();
        for param in query.split('&') {
            if let Some(eq) = param.find('=') {
                let key = &param[..eq];
                let key_lower = key.to_lowercase();
                if SENSITIVE_URL_PARAMS.iter().any(|s| key_lower == *s) {
                    parts.push(format!("{key}=[REDACTED]"));
                } else {
                    parts.push(param.to_string());
                }
            } else {
                parts.push(param.to_string());
            }
        }
        format!("{base}?{}", parts.join("&"))
    } else if url.contains("://") {
        // Strip credentials from URL (user:pass@host)
        if let Some(scheme_end) = url.find("://") {
            let after_scheme = &url[scheme_end + 3..];
            if let Some(at) = after_scheme.find('@') {
                let host_and_rest = &after_scheme[at + 1..];
                format!("{}://[REDACTED]@{}", &url[..scheme_end], host_and_rest)
            } else {
                url.to_string()
            }
        } else {
            url.to_string()
        }
    } else {
        url.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> RedactionConfig {
        RedactionConfig {
            enabled: true,
            patterns: vec![],
            replacement: "[REDACTED]".into(),
            disable_builtin: false,
        }
    }

    #[test]
    fn test_redact_github_pat() {
        let config = test_config();
        let input = "token: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij";
        let result = redact_secrets(input, &config);
        assert!(
            result.contains("[REDACTED:github-pat]"),
            "should redact GitHub PAT, got: {result}"
        );
        assert!(!result.contains("ghp_ABCDEF"));
    }

    #[test]
    fn test_redact_openai_key() {
        let config = test_config();
        let input = "key: sk-ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuv12";
        let result = redact_secrets(input, &config);
        assert!(
            result.contains("[REDACTED:"),
            "should redact OpenAI key, got: {result}"
        );
    }

    #[test]
    fn test_redact_anthropic_key() {
        let config = test_config();
        let input = "sk-ant-api03-ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnop";
        let result = redact_secrets(input, &config);
        assert!(
            result.contains("[REDACTED:anthropic-api-key]"),
            "should redact Anthropic key, got: {result}"
        );
    }

    #[test]
    fn test_redact_aws_key() {
        let config = test_config();
        let input = "AKIAIOSFODNN7EXAMPLE";
        let result = redact_secrets(input, &config);
        assert!(
            result.contains("[REDACTED:aws-access-key-id]"),
            "should redact AWS key, got: {result}"
        );
    }

    #[test]
    fn test_redact_disabled() {
        let mut config = test_config();
        config.enabled = false;
        let input = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij";
        let result = redact_secrets(input, &config);
        assert_eq!(result, input, "redaction should be skipped when disabled");
    }

    #[test]
    fn test_redact_no_secrets_unchanged() {
        let config = test_config();
        let input = "just a normal string with no secrets";
        let result = redact_secrets(input, &config);
        assert_eq!(result, input, "text without secrets should be unchanged");
    }

    #[test]
    fn test_disable_builtin_patterns() {
        let config = RedactionConfig {
            enabled: true,
            patterns: vec![],
            replacement: "[REDACTED]".into(),
            disable_builtin: true,
        };
        let input = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij";
        let result = redact_secrets(input, &config);
        assert_eq!(
            result, input,
            "builtin patterns should be skipped when disable_builtin is true"
        );
    }

    #[test]
    fn test_user_custom_patterns() {
        let config = RedactionConfig {
            enabled: true,
            patterns: vec![r"my_secret_\w+".into()],
            replacement: "[CUSTOM_REDACTED]".into(),
            disable_builtin: true,
        };
        let input = "value: my_secret_token123";
        let result = redact_secrets(input, &config);
        assert!(
            result.contains("[CUSTOM_REDACTED]"),
            "custom pattern should work, got: {result}"
        );
    }

    #[test]
    fn test_strip_invisible_unicode() {
        let input = "hello\u{E0001}\u{E0020}world";
        let result = strip_invisible_unicode(input);
        assert_eq!(result, "helloworld");
    }

    #[test]
    fn test_strip_invisible_unicode_zero_width() {
        let input = "sk-ant\u{200B}-api\u{200D}03\u{200C}-key\u{FEFF}val\u{00AD}ue";
        let result = strip_invisible_unicode(input);
        assert_eq!(result, "sk-ant-api03-keyvalue");
    }

    #[test]
    fn test_redact_url_query_params() {
        let url = "https://api.example.com/v1?token=secret123&format=json";
        let result = redact_url(url);
        assert!(result.contains("token=[REDACTED]"));
        assert!(result.contains("format=json"));
    }

    #[test]
    fn test_redact_url_credentials() {
        let url = "postgres://admin:password123@db.example.com:5432/mydb";
        let result = redact_url(url);
        assert!(result.contains("[REDACTED]@db.example.com"));
        assert!(!result.contains("password123"));
    }

    #[test]
    fn test_redact_url_no_sensitive() {
        let url = "https://example.com/path?page=1&size=10";
        let result = redact_url(url);
        assert_eq!(result, url);
    }

    #[test]
    fn test_redact_private_key() {
        let config = test_config();
        let input = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA0Z3ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdef\n-----END RSA PRIVATE KEY-----";
        let result = redact_secrets(input, &config);
        assert!(
            result.contains("[REDACTED:private-key]"),
            "should redact private key, got: {result}"
        );
    }

    #[test]
    fn test_redact_slack_token() {
        let config = test_config();
        let input = "xoxb-1234567890-abcdefghij";
        let result = redact_secrets(input, &config);
        assert!(
            result.contains("[REDACTED:slack-access-token]"),
            "should redact Slack token, got: {result}"
        );
    }

    #[test]
    fn test_redact_empty_input() {
        let config = test_config();
        let result = redact_secrets("", &config);
        assert_eq!(result, "");
    }

    #[test]
    fn test_redact_plain_text_unchanged() {
        let config = test_config();
        let input = "Hello, this is a normal log line with no secrets at all.";
        let result = redact_secrets(input, &config);
        assert_eq!(result, input);
    }

    #[test]
    fn test_redact_gitlab_pat() {
        let config = test_config();
        let input = "glpat-abcdefghij0123456789";
        let result = redact_secrets(input, &config);
        assert!(
            result.contains("[REDACTED:gitlab-pat]"),
            "should redact GitLab PAT, got: {result}"
        );
    }

    #[test]
    fn test_redact_stripe_secret() {
        let config = test_config();
        let input = "sk_test_abc123def456ghi789jklmnopqrst";
        let result = redact_secrets(input, &config);
        assert!(
            result.contains("[REDACTED:"),
            "should redact Stripe secret, got: {result}"
        );
    }

    #[test]
    fn test_redact_npm_token() {
        let config = test_config();
        let input = "npm_abcdefghijklmnopqrstuvwxyz0123456789";
        let result = redact_secrets(input, &config);
        assert!(
            result.contains("[REDACTED:npm-access-token]"),
            "should redact npm token, got: {result}"
        );
    }

    #[test]
    fn test_redact_jwt_token() {
        let config = test_config();
        let input = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
        let result = redact_secrets(input, &config);
        assert!(
            result.contains("[REDACTED:jwt-token]"),
            "should redact JWT, got: {result}"
        );
    }

    #[test]
    fn test_redact_multiple_secrets_in_one_string() {
        let config = test_config();
        let gh_pat = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij";
        let aws_key = "AKIAIOSFODNN7EXAMPLE";
        let input = format!("keys: {gh_pat} and {aws_key}");
        let result = redact_secrets(&input, &config);
        assert!(result.contains("[REDACTED:github-pat]"));
        assert!(result.contains("[REDACTED:aws-access-key-id]"));
    }

    #[test]
    fn test_redact_disabled_returns_original_2() {
        let config = RedactionConfig {
            enabled: false,
            patterns: vec![],
            replacement: "[GONE]".into(),
            disable_builtin: false,
        };
        let gh = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij";
        let result = redact_secrets(gh, &config);
        assert_eq!(result, gh);
    }

    #[test]
    fn test_redact_url_no_query_no_credentials() {
        let url = "https://example.com/path";
        assert_eq!(redact_url(url), url);
    }

    #[test]
    fn test_redact_url_multiple_sensitive_params() {
        let url = "https://api.example.com/v1?token=abc&secret=def&page=1";
        let result = redact_url(url);
        assert!(result.contains("token=[REDACTED]"));
        assert!(result.contains("secret=[REDACTED]"));
        assert!(result.contains("page=1"));
    }

    #[test]
    fn test_strip_invisible_unicode_clean_input() {
        let input = "hello world";
        assert_eq!(strip_invisible_unicode(input), "hello world");
    }

    #[test]
    fn test_strip_invisible_unicode_empty() {
        assert_eq!(strip_invisible_unicode(""), "");
    }

    #[test]
    fn test_redact_hugging_face_token() {
        let config = test_config();
        let input = "hf_AbCdEfGhIjKlMnOpQrStUvWxYz012345678901";
        let result = redact_secrets(input, &config);
        assert!(
            result.contains("[REDACTED:hugging-face-access-token]"),
            "should redact HF token, got: {result}"
        );
    }
}

#[cfg(test)]
mod extra_tests {
    use super::*;

    fn test_config() -> RedactionConfig {
        RedactionConfig {
            enabled: true,
            patterns: vec![],
            replacement: String::new(),
            disable_builtin: false,
        }
    }

    #[test]
    fn test_redact_url_query_param_without_equals() {
        let url = "https://example.com/path?bare_param&token=secret";
        let result = redact_url(url);
        assert!(result.contains("bare_param"));
        assert!(result.contains("token="));
    }

    #[test]
    fn test_redact_url_no_query_no_scheme() {
        let url = "/just/a/path";
        let result = redact_url(url);
        assert_eq!(result, url);
    }

    #[test]
    fn test_redact_twilio_api_key() {
        let config = test_config();
        let input = "SK0123456789abcdef0123456789abcdef";
        let result = redact_secrets(input, &config);
        assert!(result.contains("REDACTED"), "should redact Twilio key, got: {result}");
    }
}
