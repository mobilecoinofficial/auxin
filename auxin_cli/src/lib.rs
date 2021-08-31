#![feature(async_closure)]

pub mod app;
pub mod repl_wrapper;
pub mod state;
pub mod net;

use auxin::Result;

pub type Context = auxin::AuxinContext;

pub use crate::net::NetManager;
pub use crate::state::StateManager;
pub use crate::repl_wrapper::AppWrapper;