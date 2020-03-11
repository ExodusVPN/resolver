use crate::config::Config;

use clap::crate_version;
use clap::crate_authors;
use clap::{Arg, App, SubCommand, AppSettings};


pub fn boot() -> Result<Config, Box<dyn std::error::Error>> {
    let verbose_arg = Arg::with_name("verbose")
            .long("verbose")
            .possible_values(&["info", "warn", "error", "debug", "trace"])
            .default_value("info")
            .help("Sets the level of verbosity");
    let upstream_arg = Arg::with_name("upstream")
                        .long("upstream")
                        .multiple(true)
                        .help("Upstream name server")
                        .long_help("Example: --upstream tcp+udp+tls+https://8.8.8.8:53:53:853:443");
    let bind_arg = Arg::with_name("bind")
                .long("bind")
                .long_help("Example: --bind 'udp+tcp+tls+https://127.0.0.1:53:53:853:443'")
                .required(true)
                .takes_value(true)
                .default_value("udp+tcp://127.0.0.1:53:53");

    let tls_key_arg = Arg::with_name("tls-key")
            .long("tls-key")
            .help("TLS Server PKCS #12 Key");
    let tls_key_password_arg = Arg::with_name("tls-key-password")
            .long("tls-key-password");
    let https_key_arg = Arg::with_name("https-key")
            .long("https-key")
            .help("HTTPS Server PKCS #12 Key");
    let https_key_password_arg = Arg::with_name("https-key-password")
            .long("https-key-password");

    let mut app = App::new("Named")
        .version(crate_version!())
        .author(crate_authors!())
        .about("DNS Named/Proxy/Authoritative")
        .setting(AppSettings::ColorAuto)
        .setting(AppSettings::DisableHelpSubcommand)

        .subcommand(
            SubCommand::with_name("authoritative")
                .about("Authoritative DNS Server")
                .arg(verbose_arg.clone())
                .arg(bind_arg.clone())
                .arg(tls_key_arg.clone())
                .arg(tls_key_password_arg.clone())
                .arg(https_key_arg.clone())
                .arg(https_key_password_arg.clone())
        )
        .subcommand(
            SubCommand::with_name("recursive")
                .about("Recursive DNS Server")
                .arg(Arg::with_name("use-ipv4")
                    .long("use-ipv4")
                    .help("use ipv4"))
                .arg(Arg::with_name("use-ipv6")
                    .long("use-ipv6")
                    .help("use ipv6"))
                .arg(verbose_arg.clone())
                .arg(bind_arg.clone())
                .arg(tls_key_arg.clone())
                .arg(tls_key_password_arg.clone())
                .arg(https_key_arg.clone())
                .arg(https_key_password_arg.clone())
        )
        .subcommand(
            SubCommand::with_name("proxy")
                .about("Proxy DNS Server")
                .arg(verbose_arg.clone())
                .arg(upstream_arg.clone())
                .arg(bind_arg.clone())
                .arg(tls_key_arg.clone())
                .arg(tls_key_password_arg.clone())
                .arg(https_key_arg.clone())
                .arg(https_key_password_arg.clone())
        )
        .subcommand(
            SubCommand::with_name("stub")
                .about("stub resolver")
                // .arg(Arg::with_name("enable-mdns")
                //     .long("enable-mdns")
                //     .possible_values(&["true", "false"])
                //     .default_value("true")
                //     .help("enable mdns query"))
                // .arg(Arg::with_name("enable-hosts")
                //     .long("enable-hosts")
                //     .possible_values(&["true", "false"])
                //     .default_value("true")
                //     .help("query with system hosts file"))
                .arg(verbose_arg.clone())
                .arg(upstream_arg.clone())
                .arg(bind_arg.clone())
                .arg(tls_key_arg.clone())
                .arg(tls_key_password_arg.clone())
                .arg(https_key_arg.clone())
                .arg(https_key_password_arg.clone())
        );
    
    let mut usage = Vec::new();
    let _ = app.write_long_help(&mut usage);
    let usage = unsafe { String::from_utf8_unchecked(usage) };

    let matches = app.get_matches();
    let sub_matches = (
        matches.subcommand_matches("proxy"),
        matches.subcommand_matches("stub"),
        matches.subcommand_matches("recursive"),
        matches.subcommand_matches("authoritative"),
    );
    let (subcommand, matches) = match sub_matches {
        (Some(matches), None, None, None) => ("proxy", matches),
        (None, Some(matches), None, None) => ("stub", matches),
        (None, None, Some(matches), None) => ("recursive", matches),
        (None, None, None, Some(matches)) => ("authoritative", matches),
        _ => {
            println!("{}", usage);
            std::process::exit(1);
        }
    };

    let verbose = matches.value_of("verbose").unwrap();
    // std::env::set_var("RUST_LOG", "debug");

    // tcp+udp+tls+https://8.8.8.8:53:53:853:443
    let bind_url = matches.value_of("bind").unwrap();
    println!("bind: {}", bind_url);
    let tmp = bind_url.split("://").collect::<Vec<&str>>();


    todo!()
}