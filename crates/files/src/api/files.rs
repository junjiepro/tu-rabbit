use std::{io::{BufWriter, Write}, fs::{DirBuilder, File}, path::Path};
use chrono::prelude::*;
use actix_files::NamedFile;
use actix_multipart::Multipart;
use actix_web::{HttpResponse, web::{self, Data}, HttpRequest, Error, http::header::{ContentDisposition, DispositionType, DispositionParam}};
use futures::{TryStreamExt, StreamExt};
use data_transmission::{web::{build_http_response_error_data, build_http_response_data}, error::CommonError};
use lettre_email::mime;
use serde::{Deserialize, Serialize};

use crate::connectors::inner::FilesRootDirectory;

#[derive(Serialize, Deserialize)]
pub struct SaveFileResult {
    results: Vec<String>,
}

#[tracing::instrument(
    name = "save files handle",
    skip(need_timestamp, payload, files_root_directory)
)]
pub async fn save_files_handle(
    need_timestamp: bool,
    mut payload: Multipart,
    files_root_directory: Data::<FilesRootDirectory>,
) -> HttpResponse {
    let mut results = vec![];

    // 迭代处理 multipart 流
    while let Ok(Some(mut field)) = payload.try_next().await {
        let content_disposition = field.content_disposition();
        if let Some(filename) = content_disposition.get_filename() {
            let filepath_result = if need_timestamp {
                format!("{}_{}", Local::now().naive_local().timestamp(), sanitize_filename::sanitize(&filename))
            } else {
                format!("{}", sanitize_filename::sanitize(&filename))
            };
            let filepath = format!("{}/{}", &files_root_directory.0, &filepath_result);

            // File::create is blocking operation, use threadpool
            let f_b = match web::block(move || {
                let path = Path::new(&filepath);
                let dir = path.parent();
                if let Some(dir) = dir {
                    DirBuilder::new()
                        .recursive(true)
                        .create(dir)?;
                }
                
                File::create(&path)
            })
            .await {
                Ok(Ok(file)) => file,
                Ok(Err(e)) => {
                    return build_http_response_error_data(CommonError::UnexpectedError(e.into()));
                }
                Err(e) => {
                    return build_http_response_error_data(CommonError::UnexpectedError(e.into()));
                },
            };
            let mut f = BufWriter::new(f_b);

            // Field in turn is stream of *Bytes* object
            while let Some(chunk) = field.next().await {
                match chunk {
                    Ok(data) => {
                        // filesystem operations are blocking, we have to use threadpool
                        f = match web::block(move || f.write_all(&data).map(|_| f)).await {
                            Ok(Ok(f)) => f,
                            Ok(Err(e)) => {
                                return build_http_response_error_data(CommonError::UnexpectedError(e.into()));
                            }
                            Err(e) => {
                                return build_http_response_error_data(CommonError::UnexpectedError(e.into()));
                            },
                        };
                    },
                    Err(e) => {
                        return build_http_response_error_data(CommonError::UnexpectedError(e.into()));
                    }
                }
            }

            if let Err(e) = f.flush() {
                return build_http_response_error_data(CommonError::UnexpectedError(e.into()));
            }

            results.push(format!("{}", &filepath_result));
        }
    }
    
    build_http_response_data(SaveFileResult { results })
}

#[tracing::instrument(
    name = "save files API",
    skip(payload, files_root_directory)
)]
pub async fn save_files(
    payload: Multipart,
    files_root_directory: Data::<FilesRootDirectory>,
) -> HttpResponse {
    save_files_handle(true, payload, files_root_directory).await
}

#[tracing::instrument(
    name = "save files API",
    skip(payload, files_root_directory)
)]
pub async fn save_files_without_timestamp(
    payload: Multipart,
    files_root_directory: Data::<FilesRootDirectory>,
) -> HttpResponse {
    save_files_handle(false, payload, files_root_directory).await
}

#[derive(Debug, Deserialize)]
pub struct DownloadFile {
    filename: String,
}

#[tracing::instrument(
    name = "download file API",
    skip(download_file, req, files_root_directory)
)]
pub async fn download_file(
    download_file: web::Query<DownloadFile>,
    req: HttpRequest,
    files_root_directory: Data::<FilesRootDirectory>,
) -> Result<HttpResponse, Error> {
    let file_path = format!(
        "{}/{}",
        &files_root_directory.0,
        &download_file.filename
    );
    if let Some(file_name) = Path::new(&file_path).file_name() {
        if let Some(file_name) = file_name.to_str() {
            if let Ok(named_file) = NamedFile::open(&file_path) {
                return Ok(
                    named_file
                        .set_content_type("application/octet-stream; charset=utf-8".parse::<mime::Mime>().unwrap())
                        .set_content_disposition(
                            ContentDisposition {
                                disposition: DispositionType::Attachment,
                                parameters: vec![
                                    DispositionParam::Filename(file_name.to_string()),
                                ],
                            }
                        )
                        .into_response(&req)
                );
            }
        }
    }
    
    Ok(HttpResponse::NotFound().finish())
}