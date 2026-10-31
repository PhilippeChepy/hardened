//! serviced: PID 1 of the hardened OS. It mounts the API filesystems, pins kernel files to the
//! root and sets the hardened sysctls, reaps every process, listens on the services' sockets,
//! runs and confines the services (`libserviced::definition`), keeps their logs, and powers the
//! machine off or reboots it when asked, after stopping the services.
//!
//! Services act on it through its API (`libserviced::api`), served on a unix socket to the
//! services whose `api` grants it, which also tells them the service of a process; they tell it
//! they are ready on their notify socket (the systemd notify protocol).

mod activation_watch;
mod api_server;
mod boot_clock;
mod caller;
mod command;
mod console_writer;
mod engine;
mod exit;
mod init;
mod kernel;
mod listen_exec;
mod log_buffer;
mod log_file;
mod log_store;
mod logging;
mod method;
mod mounts;
mod notification;
mod notify_socket;
mod overview;
mod power;
mod process;
mod run;
mod sandbox;
mod service_log;
mod service_sockets;
mod service_status;
mod serviced_service;
mod shutdown;
mod shutdown_locks;
mod supervisor;

fn main() {
    if !rustix::process::getpid().is_init() {
        eprintln!("serviced: must run as PID 1");
        std::process::exit(1);
    }
    init::run()
}
