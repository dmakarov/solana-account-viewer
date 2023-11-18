// todo remove deprecated
#![allow(non_snake_case, deprecated)]

use {
    clap::{crate_description, crate_name, value_t, value_t_or_exit, values_t_or_exit, Arg, ArgMatches},
    // import the prelude to get access to the `rsx!` macro and the `Scope` and `Element` types
    dioxus::{events::{KeyCode, KeyboardEvent}, prelude::*},
    //dioxus_tui::TuiContext,
    log::*,
    //serde::{Deserialize, Serialize},
    solana_account_decoder::{UiAccount, UiAccountData, UiAccountEncoding},
    solana_accounts_db::{
        accounts::Accounts,
        accounts_db::{AccountsDb, AccountsDbConfig, FillerAccountsConfig},
        hardened_unpack::{open_genesis_config, MAX_GENESIS_ARCHIVE_UNPACKED_SIZE},
        accounts_index::{AccountsIndexConfig, IndexLimitMb},
        partitioned_rewards::TestPartitionedEpochRewards,
    },
    solana_clap_utils::{hidden_unless_forced, input_validators::{is_parsable, is_pow2, is_slot}},
    solana_core::{accounts_hash_verifier::AccountsHashVerifier, validator::BlockVerificationMethod},
    solana_gossip::{cluster_info::ClusterInfo, contact_info::ContactInfo},
    solana_ledger::{
        blockstore::{Blockstore, BlockstoreError},
        blockstore_options::{AccessType, BlockstoreOptions, BlockstoreRecoveryMode, LedgerColumnOptions, ShredStorageType},
        blockstore_processor::{self, BlockstoreProcessorError, ProcessOptions},
        use_snapshot_archives_at_startup::{self, UseSnapshotArchivesAtStartup},
        bank_forks_utils,
    },
    solana_runtime::{
        accounts_background_service::{AbsRequestHandlers, AbsRequestSender, AccountsBackgroundService, PrunedBanksRequestHandler, SnapshotRequestHandler},
        bank::TotalAccountsStats,
        bank_forks::BankForks,
        snapshot_config::SnapshotConfig,
        snapshot_hash::StartingSnapshotHashes,
        snapshot_utils::{self, clean_orphaned_account_snapshot_dirs, create_all_accounts_run_and_snapshot_dirs, move_and_async_delete_path_contents},
    },
    solana_sdk::{
        account::{AccountSharedData, ReadableAccount},
        clock::Slot, genesis_config::GenesisConfig, native_token::lamports_to_sol, pubkey::Pubkey, signature::Signer, signer::keypair::Keypair, timing::timestamp,
    },
    solana_streamer::socket::SocketAddrSpace,
    std::{collections::{BTreeMap, BTreeSet}, fs, path::{Path, PathBuf}, process::exit, sync::{atomic::{AtomicBool, Ordering}, Arc, RwLock}},
};

const LEDGER_TOOL_DIRECTORY: &str = "ledger_tool";

fn main() {
    dioxus_desktop::launch(App);
    /*
    // launch the app in the terminal
    dioxus_desktop::launch_cfg(
        App,
        dioxus_desktop::Config::new()
            .without_ctrl_c_quit()
            // Some older terminals only support 16 colors or ANSI colors
            // If your terminal is one of these, change this to BaseColors or ANSI
            .with_rendering_mode(dioxus_tui::RenderingMode::Rgb),
    );
    */
}

/// create a component that renders the top-level UI layout
fn App(cx: Scope) -> Element {
    //use_shared_state_provider(cx, || PreviewState::Unset);
    //let tui_ctx: TuiContext = cx.consume_context().unwrap();

    cx.render(rsx! {
        div {
            display: "flex",
            flex_direction: "row",
            width: "100%",
            // height: "10px",
            // background_color: "red",
            // justify_content: "center",
            // align_items: "center",
            onkeydown: move |k: KeyboardEvent| if let KeyCode::Q = k.key_code {
                //tui_ctx.quit();
            },
            div {
                display: "flex",
                flex_direction: "column",
                padding: "10px",
                Accounts {}
            }
            div {
                display: "flex",
                flex_direction: "column",
                width: "100%",
                background: "red",
                AccountItem {}
            }
        }
    })
}

fn Accounts(cx: Scope) -> Element {
    let accounts = get_accounts();

    render! {
        div {
            for account in accounts.keys() {
                AccountListing { account: account.clone() }
            }
        }
    }
}

fn AccountItem(cx: Scope) -> Element {
    render! { "account" }
}

#[inline_props]
fn AccountListing(cx: Scope, account: String) -> Element {
    cx.render(rsx! {
        div {
            position: "relative",
            font_family: "Courier",
            "{account}"
        }
    })
}

fn get_accounts() -> BTreeMap<String, Vec<String>> {
    solana_logger::setup_with_default("solana=info");

    let matches = clap::App::new(crate_name!())
        .about(crate_description!())
        .version(solana_version::version!())
        .arg(
            Arg::with_name("ledger_path")
                .short("l")
                .long("ledger")
                .value_name("DIR")
                .takes_value(true)
                .global(true)
                .default_value("ledger")
                .help("Use DIR as ledger location"),
        )
        .arg(
            Arg::with_name("wal_recovery_mode")
                .long("wal-recovery-mode")
                .value_name("MODE")
                .takes_value(true)
                .global(true)
                .possible_values(&[
                    "tolerate_corrupted_tail_records",
                    "absolute_consistency",
                    "point_in_time",
                    "skip_any_corrupted_record"])
                .help("Mode to recovery the ledger db write ahead log"),
        )
        .arg(
            Arg::with_name("force_update_to_open")
                .long("force-update-to-open")
                .takes_value(false)
                .global(true)
                .help("Allow commands that would otherwise not alter the \
                       blockstore to make necessary updates in order to open it"),
        )
        .arg(
            Arg::with_name("ignore_ulimit_nofile_error")
                .long("ignore-ulimit-nofile-error")
                .value_name("FORMAT")
                .global(true)
                .help("Allow opening the blockstore to succeed even if the desired open file \
                    descriptor limit cannot be configured. Use with caution as some commands may \
                    run fine with a reduced file descriptor limit while others will not"),
        )
        .arg(
            Arg::with_name("snapshot_archive_path")
                .long("snapshot-archive-path")
                .value_name("DIR")
                .takes_value(true)
                .global(true)
                .help("Use DIR for snapshot location"),
        )
        .arg(
            Arg::with_name("incremental_snapshot_archive_path")
                .long("incremental-snapshot-archive-path")
                .value_name("DIR")
                .takes_value(true)
                .global(true)
                .help("Use DIR for separate incremental snapshot location"),
        )
        .arg(
            Arg::with_name("block_verification_method")
                .long("block-verification-method")
                .value_name("METHOD")
                .takes_value(true)
                .possible_values(BlockVerificationMethod::cli_names())
                .global(true)
                .hidden(hidden_unless_forced())
                .help(BlockVerificationMethod::cli_message()),
        )
        .arg(
            Arg::with_name("no_snapshot")
                .long("no-snapshot")
                .takes_value(false)
                .help("Do not start from a local snapshot if present")
        )
        .arg(
            Arg::with_name("account_paths")
                .long("accounts")
                .value_name("PATHS")
                .takes_value(true)
                .help("Comma separated persistent accounts location")
        )
        .arg(
            Arg::with_name("accounts_hash_cache_path")
                .long("accounts-hash-cache-path")
                .value_name("PATH")
                .takes_value(true)
                .help("Use PATH as accounts hash cache location [default: <LEDGER>/accounts_hash_cache]")
        )
        .arg(
            Arg::with_name("accounts_index_bins")
                .long("accounts-index-bins")
                .value_name("BINS")
                .validator(is_pow2)
                .takes_value(true)
                .help("Number of bins to divide the accounts index into")
        )
        .arg(
            Arg::with_name("accounts_index_memory_limit_mb")
                .long("accounts-index-memory-limit-mb")
                .value_name("MEGABYTES")
                .validator(is_parsable::<usize>)
                .takes_value(true)
                .help("How much memory the accounts index can consume. If this is exceeded, some account index entries will be stored on disk.")
        )
        .arg(
            Arg::with_name("disable_accounts_disk_index")
                .long("disable-accounts-disk-index")
                .help("Disable the disk-based accounts index. It is enabled by default. The entire accounts index will be kept in memory.")
                .conflicts_with("accounts_index_memory_limit_mb")
        )
        .arg(
            Arg::with_name("accounts_db_verify_refcounts")
                .long("accounts-db-verify-refcounts")
                .help("Debug option to scan all AppendVecs and verify account index refcounts prior to clean")
                .hidden(hidden_unless_forced())
        )
        .arg(
            Arg::with_name("accounts_db_test_skip_rewrites")
                .long("accounts-db-test-skip-rewrites")
                .help("Debug option to skip rewrites for rent-exempt accounts but still add them in bank delta hash calculation")
                .hidden(hidden_unless_forced())
        )
        .arg(
            Arg::with_name("accounts_db_skip_initial_hash_calculation")
                .long("accounts-db-skip-initial-hash-calculation")
                .help("Do not verify accounts hash at startup.")
                .hidden(hidden_unless_forced())
        )
        .arg(
            Arg::with_name("halt_at_slot")
                .long("halt-at-slot")
                .value_name("SLOT")
                .validator(is_slot)
                .takes_value(true)
                .help("Halt processing at the given slot")
        )
        .arg(
            Arg::with_name("hard_forks")
                .long("hard-fork")
                .value_name("SLOT")
                .validator(is_slot)
                .multiple(true)
                .takes_value(true)
                .help("Add a hard fork at this slot")
        )
        .arg(
            Arg::with_name("encoding")
                .long("encoding")
                .takes_value(true)
                .possible_values(&["base64", "base64+zstd", "jsonParsed"])
                .default_value("base64")
                .help("Print account data in specified format when printing account contents.")
        )
        .arg(
            Arg::with_name(use_snapshot_archives_at_startup::cli::NAME)
                .long(use_snapshot_archives_at_startup::cli::LONG_ARG)
                .takes_value(true)
                .possible_values(use_snapshot_archives_at_startup::cli::POSSIBLE_VALUES)
                .default_value(use_snapshot_archives_at_startup::cli::default_value())
                .help(use_snapshot_archives_at_startup::cli::HELP)
                .long_help(use_snapshot_archives_at_startup::cli::LONG_HELP)
        )
        .arg(
            Arg::with_name("include_sysvars")
                .long("include-sysvars")
                .takes_value(false)
                .help("Include sysvars too"),
        )
        .get_matches();

    info!("{} {}", crate_name!(), solana_version::version!());

    let ledger_path = PathBuf::from(value_t_or_exit!(matches, "ledger_path", String));
    let snapshot_archive_path = value_t!(matches, "snapshot_archive_path", String).ok().map(PathBuf::from);
    let incremental_snapshot_archive_path = value_t!(matches, "incremental_snapshot_archive_path", String).ok().map(PathBuf::from);
    let wal_recovery_mode = matches.value_of("wal_recovery_mode").map(BlockstoreRecoveryMode::from);
    let force_update_to_open = matches.is_present("force_update_to_open");
    let enforce_ulimit_nofile = !matches.is_present("ignore_ulimit_nofile_error");
    let ledger_path = fs::canonicalize(&ledger_path).unwrap_or_else(|err| {
        eprintln!("Unable to access ledger path '{}': {}", ledger_path.display(), err);
        exit(1);
    });
    let process_options = ProcessOptions {
        new_hard_forks: if matches.is_present("hard_forks") {Some(values_t_or_exit!(matches, "hard_forks", Slot))} else {None},
        halt_at_slot: value_t!(matches, "halt_at_slot", Slot).ok(),
        run_verification: false,
        accounts_db_config: Some(get_accounts_db_config(&ledger_path, &matches)),
        use_snapshot_archives_at_startup: value_t_or_exit!(
            matches,
            use_snapshot_archives_at_startup::cli::NAME,
            UseSnapshotArchivesAtStartup
        ),
        ..ProcessOptions::default()
    };
    let genesis_config = open_genesis_config(&ledger_path, MAX_GENESIS_ARCHIVE_UNPACKED_SIZE);
    let include_sysvars = matches.is_present("include_sysvars");
    let access_type = match process_options.use_snapshot_archives_at_startup {
        UseSnapshotArchivesAtStartup::Always => AccessType::Secondary,
        UseSnapshotArchivesAtStartup::Never => AccessType::PrimaryForMaintenance,
        UseSnapshotArchivesAtStartup::WhenNewest => AccessType::PrimaryForMaintenance,
    };
    let blockstore = open_blockstore(&ledger_path, access_type, wal_recovery_mode, force_update_to_open, enforce_ulimit_nofile);
    let (bank_forks, ..) = load_and_process_ledger(&matches, &genesis_config, Arc::new(blockstore), process_options, snapshot_archive_path, incremental_snapshot_archive_path)
        .unwrap_or_else(|err| {
            eprintln!("Failed to load ledger: {err:?}");
            exit(1);
        });
    let bank = bank_forks.read().unwrap().working_bank();
    let mut total_accounts_stats = TotalAccountsStats::default();
    let rent_collector = bank.rent_collector();
    let data_encoding = match matches.value_of("encoding") {
        Some("jsonParsed") => UiAccountEncoding::JsonParsed,
        Some("base64") => UiAccountEncoding::Base64,
        Some("base64+zstd") => UiAccountEncoding::Base64Zstd,
        _ => UiAccountEncoding::Base64,
    };
    let mut owners: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut account_set: BTreeSet<String> = BTreeSet::new();
    let scan_func = |some_account_tuple: Option<(&Pubkey, AccountSharedData, Slot)>| {
        if let Some((pubkey, account, slot)) = some_account_tuple
            .filter(|(_, account, _)| Accounts::is_loadable(account.lamports()))
        {
            if include_sysvars || !solana_sdk::sysvar::is_sysvar_id(pubkey) {
                total_accounts_stats.accumulate_account(pubkey, &account, rent_collector);
                let key = account.owner().to_string();
                let account_key = pubkey.to_string();
                account_set.insert(account_key.clone());
                if let Some(accounts) = owners.get_mut(&key) {
                    accounts.push(account_key);
                } else {
                    owners.insert(key, vec![account_key]);
                }
                output_account(pubkey, &account, Some(slot), false, data_encoding);
            }
        }
    };
    bank.scan_all_accounts(scan_func).unwrap();
    println!("\n{total_accounts_stats:#?}");
    owners.into_iter().filter(|(k, _)| !account_set.contains(k)).collect()
}

// Build an `AccountsDbConfig` from subcommand arguments. All of the arguments
// matched by this functional are either optional or have a default value.
// Thus, a subcommand need not support all of the arguments that are matched
// by this function.
fn get_accounts_db_config(ledger_path: &Path, arg_matches: &ArgMatches<'_>,) -> AccountsDbConfig {
    let ledger_tool_ledger_path = ledger_path.join(LEDGER_TOOL_DIRECTORY);
    let accounts_index_bins = value_t!(arg_matches, "accounts_index_bins", usize).ok();
    let accounts_index_index_limit_mb =
        if let Ok(limit) = value_t!(arg_matches, "accounts_index_memory_limit_mb", usize) {
            IndexLimitMb::Limit(limit)
        } else if arg_matches.is_present("disable_accounts_disk_index") {
            IndexLimitMb::InMemOnly
        } else {
            IndexLimitMb::Unspecified
        };
    let test_partitioned_epoch_rewards =
        if arg_matches.is_present("partitioned_epoch_rewards_compare_calculation") {
            TestPartitionedEpochRewards::CompareResults
        } else if arg_matches.is_present("partitioned_epoch_rewards_force_enable_single_slot") {
            TestPartitionedEpochRewards::ForcePartitionedEpochRewardsInOneBlock
        } else {
            TestPartitionedEpochRewards::None
        };
    let accounts_index_drives: Vec<PathBuf> = if arg_matches.is_present("accounts_index_path") {
        values_t_or_exit!(arg_matches, "accounts_index_path", String).into_iter().map(PathBuf::from).collect()
    } else {
        vec![ledger_tool_ledger_path.join("accounts_index")]
    };
    let accounts_index_config = AccountsIndexConfig {
        bins: accounts_index_bins,
        index_limit_mb: accounts_index_index_limit_mb,
        drives: Some(accounts_index_drives),
        ..AccountsIndexConfig::default()
    };
    let filler_accounts_config = FillerAccountsConfig {
        count: value_t!(arg_matches, "accounts_filler_count", usize).unwrap_or(0),
        size: value_t!(arg_matches, "accounts_filler_size", usize).unwrap_or(0),
    };
    let accounts_hash_cache_path = arg_matches
        .value_of("accounts_hash_cache_path")
        .map(Into::into)
        .unwrap_or_else(|| ledger_tool_ledger_path.join(AccountsDb::DEFAULT_ACCOUNTS_HASH_CACHE_DIR));
    let accounts_hash_cache_path =
        snapshot_utils::create_and_canonicalize_directories(&[accounts_hash_cache_path])
            .unwrap_or_else(|err| {
                eprintln!("Unable to access accounts hash cache path: {err}");
                std::process::exit(1);
            })
            .pop()
            .unwrap();
    AccountsDbConfig {
        index: Some(accounts_index_config),
        base_working_path: Some(ledger_tool_ledger_path),
        accounts_hash_cache_path: Some(accounts_hash_cache_path),
        filler_accounts_config,
        ancient_append_vec_offset: value_t!(arg_matches, "accounts_db_ancient_append_vecs", i64).ok(),
        exhaustively_verify_refcounts: arg_matches.is_present("accounts_db_verify_refcounts"),
        skip_initial_hash_calc: arg_matches.is_present("accounts_db_skip_initial_hash_calculation"),
        test_partitioned_epoch_rewards,
        test_skip_rewrites_but_include_in_bank_hash: arg_matches.is_present("accounts_db_test_skip_rewrites"),
        ..AccountsDbConfig::default()
    }
}

fn load_and_process_ledger(
    arg_matches: &ArgMatches,
    genesis_config: &GenesisConfig,
    blockstore: Arc<Blockstore>,
    process_options: ProcessOptions,
    snapshot_archive_path: Option<PathBuf>,
    incremental_snapshot_archive_path: Option<PathBuf>,
) -> Result<(Arc<RwLock<BankForks>>, Option<StartingSnapshotHashes>), BlockstoreProcessorError> {
    let bank_snapshots_dir = if blockstore.is_primary_access() {
        blockstore.ledger_path().join("snapshot")
    } else {
        blockstore.ledger_path().join(LEDGER_TOOL_DIRECTORY).join("snapshot")
    };

    let mut starting_slot = 0; // default start check with genesis
    let snapshot_config = if arg_matches.is_present("no_snapshot") {
        None
    } else {
        let full_snapshot_archives_dir =
            snapshot_archive_path.unwrap_or_else(|| blockstore.ledger_path().to_path_buf());
        let incremental_snapshot_archives_dir =
            incremental_snapshot_archive_path.unwrap_or_else(|| full_snapshot_archives_dir.clone());
        if let Some(full_snapshot_slot) =
            snapshot_utils::get_highest_full_snapshot_archive_slot(&full_snapshot_archives_dir)
        {
            let incremental_snapshot_slot =
                snapshot_utils::get_highest_incremental_snapshot_archive_slot(
                    &incremental_snapshot_archives_dir,
                    full_snapshot_slot,
                )
                .unwrap_or_default();
            starting_slot = std::cmp::max(full_snapshot_slot, incremental_snapshot_slot);
        }

        Some(SnapshotConfig {
            full_snapshot_archives_dir,
            incremental_snapshot_archives_dir,
            bank_snapshots_dir: bank_snapshots_dir.clone(),
            ..SnapshotConfig::new_load_only()
        })
    };

    let start_slot_msg = "The starting slot will be the latest snapshot slot, or genesis if \
        the --no-snapshot flag is specified or if no snapshots are found.";
    match process_options.halt_at_slot {
        // Skip the following checks for sentinel values of Some(0) and None.
        // For Some(0), no slots will be be replayed after starting_slot.
        // For None, all available children of starting_slot will be replayed.
        None | Some(0) => {}
        Some(halt_slot) => {
            if halt_slot < starting_slot {
                eprintln!(
                    "Unable to process blockstore from starting slot {starting_slot} to \
                    {halt_slot}; the ending slot is less than the starting slot. {start_slot_msg}"
                );
                exit(1);
            }
            // Check if we have the slot data necessary to replay from starting_slot to >= halt_slot.
            if !blockstore.slot_range_connected(starting_slot, halt_slot) {
                eprintln!(
                    "Unable to process blockstore from starting slot {starting_slot} to \
                    {halt_slot}; the blockstore does not contain a replayable chain between these \
                    slots. {start_slot_msg}"
                );
                exit(1);
            }
        }
    }

    let account_paths = if let Some(account_paths) = arg_matches.value_of("account_paths") {
        // If this blockstore access is Primary, no other process (solana-validator) can hold
        // Primary access. So, allow a custom accounts path without worry of wiping the accounts
        // of solana-validator.
        if !blockstore.is_primary_access() {
            // Attempt to open the Blockstore in Primary access; if successful, no other process
            // was holding Primary so allow things to proceed with custom accounts path. Release
            // the Primary access instead of holding it to give priority to solana-validator over
            // solana-ledger-tool should solana-validator start before we've finished.
            info!(
                "Checking if another process currently holding Primary access to {:?}",
                blockstore.ledger_path()
            );
            if Blockstore::open_with_options(
                blockstore.ledger_path(),
                BlockstoreOptions {
                    access_type: AccessType::PrimaryForMaintenance,
                    ..BlockstoreOptions::default()
                },
            )
            .is_err()
            {
                // Couldn't get Primary access, error out to be defensive.
                eprintln!("Error: custom accounts path is not supported under secondary access");
                exit(1);
            }
        }
        account_paths.split(',').map(PathBuf::from).collect()
    } else if blockstore.is_primary_access() {
        vec![blockstore.ledger_path().join("accounts")]
    } else {
        let non_primary_accounts_path = blockstore
            .ledger_path()
            .join(LEDGER_TOOL_DIRECTORY)
            .join("accounts");
        info!(
            "Default accounts path is switched aligning with Blockstore's secondary access: {:?}",
            non_primary_accounts_path
        );
        vec![non_primary_accounts_path]
    };

    let (account_run_paths, account_snapshot_paths) =
        create_all_accounts_run_and_snapshot_dirs(&account_paths).unwrap_or_else(|err| {
            eprintln!("Error: {err}");
            exit(1);
        });

    // From now on, use run/ paths in the same way as the previous account_paths.
    let account_paths = account_run_paths;

    account_paths.iter().for_each(|path| {
        if path.exists() {
            info!("Cleaning contents of account path: {}", path.display());
            move_and_async_delete_path_contents(path);
        }
    });

    snapshot_utils::purge_incomplete_bank_snapshots(&bank_snapshots_dir);

    info!("Cleaning contents of account snapshot paths: {account_snapshot_paths:?}");
    if let Err(err) =
        clean_orphaned_account_snapshot_dirs(&bank_snapshots_dir, &account_snapshot_paths)
    {
        eprintln!("Failed to clean orphaned account snapshot dirs: {err}");
        exit(1);
    }

    let exit = Arc::new(AtomicBool::new(false));
    let (bank_forks, leader_schedule_cache, starting_snapshot_hashes, ..) =
        bank_forks_utils::load_bank_forks(
            genesis_config,
            blockstore.as_ref(),
            account_paths,
            None,
            snapshot_config.as_ref(),
            &process_options,
            None,
            None, // Maybe support this later, though
            None,
            exit.clone(),
        );
    let block_verification_method = value_t!(
        arg_matches,
        "block_verification_method",
        BlockVerificationMethod
    )
    .unwrap_or_default();
    info!(
        "Using: block-verification-method: {}",
        block_verification_method,
    );

    let node_id = Arc::new(Keypair::new());
    let cluster_info = Arc::new(ClusterInfo::new(
        ContactInfo::new_localhost(&node_id.pubkey(), timestamp()),
        Arc::clone(&node_id),
        SocketAddrSpace::Unspecified,
    ));
    let (accounts_package_sender, accounts_package_receiver) = crossbeam_channel::unbounded();
    let accounts_hash_verifier = AccountsHashVerifier::new(
        accounts_package_sender.clone(),
        accounts_package_receiver,
        None,
        exit.clone(),
        cluster_info,
        None,
        SnapshotConfig::new_load_only(),
    );
    let (snapshot_request_sender, snapshot_request_receiver) = crossbeam_channel::unbounded();
    let accounts_background_request_sender = AbsRequestSender::new(snapshot_request_sender.clone());
    let snapshot_request_handler = SnapshotRequestHandler {
        snapshot_config: SnapshotConfig::new_load_only(),
        snapshot_request_sender,
        snapshot_request_receiver,
        accounts_package_sender,
    };
    let pruned_banks_receiver =
        AccountsBackgroundService::setup_bank_drop_callback(bank_forks.clone());
    let pruned_banks_request_handler = PrunedBanksRequestHandler {
        pruned_banks_receiver,
    };
    let abs_request_handler = AbsRequestHandlers {
        snapshot_request_handler,
        pruned_banks_request_handler,
    };
    let accounts_background_service = AccountsBackgroundService::new(
        bank_forks.clone(),
        exit.clone(),
        abs_request_handler,
        process_options.accounts_db_test_hash_calculation,
        None,
    );

    let result = blockstore_processor::process_blockstore_from_root(
        blockstore.as_ref(),
        &bank_forks,
        &leader_schedule_cache,
        &process_options,
        None,
        None,
        None,
        &accounts_background_request_sender,
    )
    .map(|_| (bank_forks, starting_snapshot_hashes));

    exit.store(true, Ordering::Relaxed);
    accounts_background_service.join().unwrap();
    accounts_hash_verifier.join().unwrap();
    result
}

fn open_blockstore(
    ledger_path: &Path,
    access_type: AccessType,
    wal_recovery_mode: Option<BlockstoreRecoveryMode>,
    force_update_to_open: bool,
    enforce_ulimit_nofile: bool,
) -> Blockstore {
    let shred_storage_type = match ShredStorageType::from_ledger_path(ledger_path, None) {
        Some(s) => s,
        None => {
            info!("Shred storage type cannot be inferred for ledger at {ledger_path:?}, using default RocksLevel");
            ShredStorageType::RocksLevel
        }
    };

    match Blockstore::open_with_options(
        ledger_path,
        BlockstoreOptions {
            access_type: access_type.clone(),
            recovery_mode: wal_recovery_mode.clone(),
            enforce_ulimit_nofile,
            column_options: LedgerColumnOptions {
                shred_storage_type,
                ..LedgerColumnOptions::default()
            },
        },
    ) {
        Ok(blockstore) => blockstore,
        Err(BlockstoreError::RocksDb(err)) => {
            // Missing essential file, indicative of blockstore not existing
            let missing_blockstore = err
                .to_string()
                .starts_with("IO error: No such file or directory:");
            // Missing column in blockstore that is expected by software
            let missing_column = err
                .to_string()
                .starts_with("Invalid argument: Column family not found:");
            // The blockstore settings with Primary access can resolve the
            // above issues automatically, so only emit the help messages
            // if access type is Secondary
            let is_secondary = access_type == AccessType::Secondary;

            if missing_blockstore && is_secondary {
                eprintln!(
                    "Failed to open blockstore at {ledger_path:?}, it \
                    is missing at least one critical file: {err:?}"
                );
            } else if missing_column && is_secondary {
                eprintln!(
                    "Failed to open blockstore at {ledger_path:?}, it \
                    does not have all necessary columns: {err:?}"
                );
            } else {
                eprintln!("Failed to open blockstore at {ledger_path:?}: {err:?}");
                exit(1);
            }
            if !force_update_to_open {
                eprintln!("Use --force-update-to-open flag to attempt to update the blockstore");
                exit(1);
            }
            open_blockstore_with_temporary_primary_access(
                ledger_path,
                access_type,
                wal_recovery_mode,
            )
            .unwrap_or_else(|err| {
                eprintln!("Failed to open blockstore (with --force-update-to-open) at {:?}: {:?}", ledger_path, err);
                exit(1);
            })
        }
        Err(err) => {
            eprintln!("Failed to open blockstore at {ledger_path:?}: {err:?}");
            exit(1);
        }
    }
}

/// Open blockstore with temporary primary access to allow necessary,
/// persistent changes to be made to the blockstore (such as creation of new
/// column family(s)). Then, continue opening with `original_access_type`
fn open_blockstore_with_temporary_primary_access(
    ledger_path: &Path,
    original_access_type: AccessType,
    wal_recovery_mode: Option<BlockstoreRecoveryMode>,
) -> Result<Blockstore, BlockstoreError> {
    // Open with Primary will allow any configuration that automatically
    // updates to take effect
    info!("Attempting to temporarily open blockstore with Primary access in order to update");
    {
        let _ = Blockstore::open_with_options(
            ledger_path,
            BlockstoreOptions {
                access_type: AccessType::PrimaryForMaintenance,
                recovery_mode: wal_recovery_mode.clone(),
                enforce_ulimit_nofile: true,
                ..BlockstoreOptions::default()
            },
        )?;
    }
    // Now, attempt to open the blockstore with original AccessType
    info!("Blockstore forced open succeeded, retrying with original access: {original_access_type:?}");
    Blockstore::open_with_options(
        ledger_path,
        BlockstoreOptions {
            access_type: original_access_type,
            recovery_mode: wal_recovery_mode,
            enforce_ulimit_nofile: true,
            ..BlockstoreOptions::default()
        },
    )
}

fn output_account(
    pubkey: &Pubkey,
    account: &AccountSharedData,
    modified_slot: Option<Slot>,
    print_account_data: bool,
    encoding: UiAccountEncoding,
) {
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
    println!("{:>6} {pubkey}:", COUNTER.fetch_add(1, std::sync::atomic::Ordering::SeqCst));
    println!("  balance:    {} SOL", lamports_to_sol(account.lamports()));
    println!("  owner:      '{}'", account.owner());
    println!("  executable: {}", account.executable());
    if let Some(slot) = modified_slot {
        println!("  slot:       {slot}");
    }
    println!("  rent_epoch: {}", account.rent_epoch());
    println!("  data_len:   {}", account.data().len());
    if print_account_data {
        let account_data = UiAccount::encode(pubkey, account, encoding, None, None).data;
        match account_data {
            UiAccountData::Binary(data, data_encoding) => {
                println!("  data: '{data}'");
                println!("  encoding: {}", serde_json::to_string(&data_encoding).unwrap());
            }
            UiAccountData::Json(account_data) => {
                println!("  data: '{}'", serde_json::to_string(&account_data).unwrap());
                println!("  encoding: \"jsonParsed\"");
            }
            UiAccountData::LegacyBinary(_) => {}
        };
    }
}
