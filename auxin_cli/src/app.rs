use auxin::AuxinApp;
use rand::rngs::OsRng;

use crate::{net::NetManager, state::StateManager};

pub type App = AuxinApp<OsRng, NetManager, StateManager>;
