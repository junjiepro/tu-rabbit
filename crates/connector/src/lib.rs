//! 连接器
//! 
//! # Examples
//! ```rust,compile_fail
//! use connector::{ConnectorBuilder, ConnectorService};
//! 
//! let connector_builder1 = /* ConnectorBuilder */;
//! let connector_server1 = connector_builder1.build_connector_server();
//! let connector_server1 = Data::new(connector_server1);
//! let connector_builder2 = /* ConnectorBuilder */;
//! let connector_server2 = connector_builder2.build_connector_server();
//! let connector_server2 = Data::new(connector_server2);
//! let server = HttpServer::new(move || {
//!         App::new()
//!             .wrap(TracingLogger::default())
//!             .service(
//!                 web::scope("")
//!                     .wrap(from_fn(/* middleware_fn1 */))
//!                     .wrap(from_fn(/* middleware_fn2 */))
//!                     .connector_server("/authentication", connector_server1.get_ref())
//!                     .connector_server("/data", connector_server2.get_ref())
//!             )
//!     })
//!     .workers(1)
//!     .listen(listener)?
//!     .run();
//! ```

mod connector_tratit;

pub use connector_tratit::*;