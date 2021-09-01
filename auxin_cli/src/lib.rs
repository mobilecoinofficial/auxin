#![feature(async_closure)]

pub mod app;
pub mod net;
pub mod repl_wrapper;
pub mod state;

use auxin::Result;

pub type Context = auxin::AuxinContext;

pub use crate::net::NetManager;
pub use crate::repl_wrapper::AppWrapper;
pub use crate::state::StateManager;
