// Copyright (c) 2019 Ant Financial
// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use crate::linux_abi::pcipath_from_dev_tree_path;
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;
use std::sync::Arc;

use anyhow::{anyhow, bail, Context, Result};
#[cfg(target_arch = "s390x")]
use kata_types::device::DRIVER_BLK_CCW_TYPE;
use kata_types::device::{
    DRIVER_BLK_MMIO_TYPE, DRIVER_BLK_PCI_TYPE, DRIVER_NVDIMM_TYPE, DRIVER_SCSI_TYPE,
};
use kata_types::mount::{StorageDevice, KATA_BLOCK_VOLUME_CREATE_FS};
use nix::sys::stat::{major, minor};
use protocols::agent::Storage;
use tracing::instrument;

#[cfg(target_arch = "s390x")]
use crate::ccw;
#[cfg(target_arch = "s390x")]
use crate::device::block_device_handler::get_virtio_blk_ccw_device_name;
use crate::device::block_device_handler::{
    get_virtio_blk_mmio_device_name, get_virtio_blk_pci_device_name,
};
use crate::device::nvdimm_device_handler::wait_for_pmem_device;
use crate::device::scsi_device_handler::get_scsi_device_name;
use crate::storage::{
    common_storage_handler, new_device, set_ownership, StorageContext, StorageHandler,
};
use slog::Logger;
#[cfg(target_arch = "s390x")]
use std::str::FromStr;

const EPHEMERAL_ENCRYPTION_DRIVER_OPTION: &str = "encryption_key=ephemeral";
const MKFS_EXT4: &str = "mkfs.ext4";
const BLOCK_EMPTYDIR_EXT4_MKFS_OPTS: [&str; 8] =
    ["-O", "^has_journal", "-m", "0", "-i", "163840", "-I", "128"];

#[derive(Debug, Eq, PartialEq)]
struct BlockStorageDriverOptions {
    has_ephemeral_encryption: bool,
    should_create_filesystem: bool,
}

fn get_device_number(dev_path: &str, metadata: Option<&fs::Metadata>) -> Result<String> {
    let dev_id = match metadata {
        Some(m) => m.rdev(),
        None => {
            let m =
                fs::metadata(dev_path).context(format!("get metadata on file {:?}", dev_path))?;
            m.rdev()
        }
    };
    Ok(format!("{}:{}", major(dev_id), minor(dev_id)))
}

async fn handle_block_storage(
    logger: &Logger,
    storage: &Storage,
    dev_num: &str,
) -> Result<Arc<dyn StorageDevice>> {
    // A non-"ephemeral" `encryption_key=<uri>` (kbs://) selects a PERSISTENT
    // on-device LUKS2 volume whose passphrase is released by CDH after the
    // guest is attested. First use formats the device; later boots re-open the
    // same ciphertext. Encrypted + persistent + unprivileged (the measured
    // agent mounts, so the workload needs no CAP_SYS_ADMIN). This is distinct
    // from the "ephemeral" path below, which wipes the device every boot.
    if let Some(key_uri) = persistent_luks_key_uri(storage) {
        return persistent_luks_storage(logger, storage, key_uri).await;
    }

    let options = block_storage_driver_options(storage)?;

    if options.has_ephemeral_encryption {
        let mkfs_opts = BLOCK_EMPTYDIR_EXT4_MKFS_OPTS.join(" ");
        crate::rpc::cdh_secure_mount(
            "block-device",
            dev_num,
            "luks2",
            &storage.mount_point,
            &mkfs_opts,
        )
        .await?;
        set_ownership(logger, storage)?;
        new_device(storage.mount_point.clone())
    } else {
        if options.should_create_filesystem {
            ensure_block_filesystem(logger, storage).await?;
        }
        let path = common_storage_handler(logger, storage)?;
        new_device(path)
    }
}

fn block_storage_driver_options(storage: &Storage) -> Result<BlockStorageDriverOptions> {
    let has_ephemeral_encryption = storage
        .driver_options
        .iter()
        .any(|opt| opt == EPHEMERAL_ENCRYPTION_DRIVER_OPTION);
    let should_create_filesystem = should_create_block_filesystem(storage);

    if has_ephemeral_encryption && !should_create_filesystem {
        return Err(anyhow!(
            "{} requires {} for block storage",
            EPHEMERAL_ENCRYPTION_DRIVER_OPTION,
            KATA_BLOCK_VOLUME_CREATE_FS
        ));
    }

    Ok(BlockStorageDriverOptions {
        has_ephemeral_encryption,
        should_create_filesystem,
    })
}

fn should_create_block_filesystem(storage: &Storage) -> bool {
    storage
        .driver_options
        .iter()
        .any(|opt| opt == KATA_BLOCK_VOLUME_CREATE_FS)
}

async fn ensure_block_filesystem(logger: &Logger, storage: &Storage) -> Result<()> {
    match storage.fstype.as_str() {
        "ext4" => ensure_ext4_filesystem(logger, &storage.source).await,
        _ => Err(anyhow!(
            "creating filesystem {} for block storage is unsupported",
            storage.fstype
        )),
    }
}

async fn ensure_ext4_filesystem(logger: &Logger, source: &str) -> Result<()> {
    // This option is emitted for block emptyDir volumes, whose backing device
    // is ephemeral and freshly allocated for the pod.
    info!(logger, "creating ext4 filesystem"; "source" => source);
    let output = {
        // Keep the agent SIGCHLD handler from reaping this child before
        // tokio::process observes it.
        let _locker = rustjail::container::WAIT_PID_LOCKER.lock().await;
        // BLOCK_EMPTYDIR_EXT4_MKFS_OPTS mirrors CDH's EXT4_INTEGRITY_MKFS_OPTS
        // from confidential-data-hub/hub/src/storage/volume_type/blockdevice/mod.rs.
        // CDH's FsFormatter adds "-F" and its mapped device path separately in
        // confidential-data-hub/hub/src/storage/drivers/filesystem.rs; here the
        // agent invokes mkfs.ext4 directly, so add "-F" and source below.
        tokio::process::Command::new(MKFS_EXT4)
            .arg("-F")
            .args(BLOCK_EMPTYDIR_EXT4_MKFS_OPTS)
            .arg(source)
            .output()
            .await
            .with_context(|| format!("run {MKFS_EXT4} for {source}"))?
    };

    if output.status.success() {
        return Ok(());
    }

    Err(anyhow!(
        "{} failed for {}: status={}, stdout={}, stderr={}",
        MKFS_EXT4,
        source,
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    ))
}

/// Search path for cryptsetup / mkfs. The confidential GPU rootfs ships them
/// under /usr/sbin and /sbin.
const STORAGE_TOOL_PATH: &str = "/usr/sbin:/sbin:/usr/bin:/bin";

/// A persistent LUKS key URI, if `driver_options` carries `encryption_key=<uri>`
/// with a value other than the "ephemeral" literal. Delivered from a
/// direct-volume's `metadata.encryptionKey`.
fn persistent_luks_key_uri(storage: &Storage) -> Option<&str> {
    storage
        .driver_options
        .iter()
        .find_map(|o| o.strip_prefix("encryption_key="))
        .filter(|v| !v.is_empty() && *v != "ephemeral")
}

/// Deterministic /dev/mapper name derived from the mount point (FNV-1a), so a
/// re-open within the same PodVM finds a stable name and cannot collide with an
/// unrelated volume.
fn luks_mapper_name(mount_point: &str) -> String {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in mount_point.as_bytes() {
        h ^= *b as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    format!("kcache-{:016x}", h)
}

/// Fetch the LUKS passphrase referenced by a `kbs://` URI from CDH. CDH only
/// releases it once the guest quote satisfies the KBS resource policy, so the
/// key never exists on the host.
async fn fetch_luks_key(key_uri: &str) -> Result<Vec<u8>> {
    if !crate::confidential_data_hub::is_cdh_client_initialized() {
        bail!("CDH client not initialized; cannot resolve persistent LUKS key {key_uri}");
    }
    match key_uri.strip_prefix("kbs://") {
        // get_cdh_resource re-prepends "kbs://", so pass the remainder.
        Some(path) => crate::confidential_data_hub::get_cdh_resource(path)
            .await
            .with_context(|| format!("CDH get_resource for {key_uri}")),
        None => bail!("unsupported persistent LUKS key scheme in {key_uri} (only kbs:// is supported)"),
    }
}

/// Run a cryptsetup subcommand with an optional passphrase on stdin. Mirrors
/// `ensure_ext4_filesystem`: holds WAIT_PID_LOCKER so the agent SIGCHLD handler
/// does not reap the child before tokio observes it.
async fn run_cryptsetup(args: &[&str], stdin_data: Option<&[u8]>) -> Result<()> {
    use std::process::Stdio;
    use tokio::io::AsyncWriteExt;

    let _locker = rustjail::container::WAIT_PID_LOCKER.lock().await;
    let mut cmd = tokio::process::Command::new("cryptsetup");
    cmd.args(args)
        .env("PATH", STORAGE_TOOL_PATH)
        .stdin(if stdin_data.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = cmd.spawn().context("spawn cryptsetup")?;
    if let Some(data) = stdin_data {
        let mut stdin = child
            .stdin
            .take()
            .ok_or_else(|| anyhow!("no stdin handle for cryptsetup"))?;
        stdin
            .write_all(data)
            .await
            .context("write passphrase to cryptsetup")?;
        // Drop closes the pipe so cryptsetup sees EOF.
    }
    let output = child
        .wait_with_output()
        .await
        .context("wait for cryptsetup")?;
    if !output.status.success() {
        bail!(
            "cryptsetup {:?} failed: status={}, stderr={}",
            args,
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(())
}

/// True if `device` already carries a LUKS2 header (formatted on a previous
/// boot). Never errors — a blank device is simply "not LUKS".
async fn device_is_luks(device: &str) -> bool {
    let _locker = rustjail::container::WAIT_PID_LOCKER.lock().await;
    tokio::process::Command::new("cryptsetup")
        .args(["isLuks", device])
        .env("PATH", STORAGE_TOOL_PATH)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .await
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Open (or, on first use, format) a persistent on-device LUKS2 volume with a
/// KBS-released passphrase, then mount the decrypted mapper via the normal
/// block-storage path. Unprivileged from the workload's point of view.
async fn persistent_luks_storage(
    logger: &Logger,
    storage: &Storage,
    key_uri: &str,
) -> Result<Arc<dyn StorageDevice>> {
    let device = storage.source.clone();
    if device.is_empty() {
        bail!("persistent-luks: storage source device is empty");
    }

    let passphrase = fetch_luks_key(key_uri).await?;
    let mapper = luks_mapper_name(&storage.mount_point);
    let mapper_path = format!("/dev/mapper/{mapper}");

    if device_is_luks(&device).await {
        info!(logger, "persistent-luks: opening existing LUKS2 volume";
            "device" => device.as_str(), "mapper" => mapper.as_str());
        run_cryptsetup(&["luksOpen", "-d", "-", device.as_str(), mapper.as_str()], Some(&passphrase))
            .await
            .context("luksOpen existing volume")?;
    } else {
        info!(logger, "persistent-luks: formatting new LUKS2 volume (first use)";
            "device" => device.as_str(), "mapper" => mapper.as_str());
        run_cryptsetup(
            &[
                "--batch-mode",
                "luksFormat",
                "--type",
                "luks2",
                "--cipher",
                "aes-xts-plain64",
                "--sector-size",
                "4096",
                device.as_str(),
                "-",
            ],
            Some(&passphrase),
        )
        .await
        .context("luksFormat new volume")?;
        run_cryptsetup(&["luksOpen", "-d", "-", device.as_str(), mapper.as_str()], Some(&passphrase))
            .await
            .context("luksOpen after format")?;
        ensure_ext4_filesystem(logger, &mapper_path)
            .await
            .context("mkfs.ext4 on new volume")?;
    }

    // Mount the plaintext mapper device via the normal block-storage path. Drop
    // our synthetic driver option so it is not mistaken for a mount option.
    let mut mapped = storage.clone();
    mapped.source = mapper_path;
    if mapped.fstype.is_empty() {
        mapped.fstype = "ext4".to_string();
    }
    mapped.driver_options = Vec::new();
    let path = common_storage_handler(logger, &mapped)?;
    new_device(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn storage_with_driver_options(options: &[&str]) -> Storage {
        Storage {
            driver_options: options.iter().map(|opt| opt.to_string()).collect(),
            ..Default::default()
        }
    }

    #[test]
    fn block_storage_options_allow_normal_existing_storage() {
        let storage = storage_with_driver_options(&[]);

        let options = block_storage_driver_options(&storage).unwrap();

        assert_eq!(
            options,
            BlockStorageDriverOptions {
                has_ephemeral_encryption: false,
                should_create_filesystem: false,
            }
        );
    }

    #[test]
    fn block_storage_options_allow_plain_fresh_storage() {
        let storage = storage_with_driver_options(&[KATA_BLOCK_VOLUME_CREATE_FS]);

        let options = block_storage_driver_options(&storage).unwrap();

        assert_eq!(
            options,
            BlockStorageDriverOptions {
                has_ephemeral_encryption: false,
                should_create_filesystem: true,
            }
        );
    }

    #[test]
    fn block_storage_options_allow_encrypted_fresh_storage() {
        let storage = storage_with_driver_options(&[
            EPHEMERAL_ENCRYPTION_DRIVER_OPTION,
            KATA_BLOCK_VOLUME_CREATE_FS,
        ]);

        let options = block_storage_driver_options(&storage).unwrap();

        assert_eq!(
            options,
            BlockStorageDriverOptions {
                has_ephemeral_encryption: true,
                should_create_filesystem: true,
            }
        );
    }

    #[test]
    fn block_storage_options_reject_encryption_without_filesystem_creation() {
        let storage = storage_with_driver_options(&[EPHEMERAL_ENCRYPTION_DRIVER_OPTION]);

        let err = block_storage_driver_options(&storage).unwrap_err();

        assert!(err.to_string().contains(KATA_BLOCK_VOLUME_CREATE_FS));
    }
}

#[derive(Debug)]
pub struct VirtioBlkMmioHandler {}

#[async_trait::async_trait]
impl StorageHandler for VirtioBlkMmioHandler {
    #[instrument]
    fn driver_types(&self) -> &[&str] {
        &[DRIVER_BLK_MMIO_TYPE]
    }

    #[instrument]
    async fn create_device(
        &self,
        storage: Storage,
        ctx: &mut StorageContext,
    ) -> Result<Arc<dyn StorageDevice>> {
        if !Path::new(&storage.source).exists() {
            get_virtio_blk_mmio_device_name(ctx.sandbox, &storage.source)
                .await
                .context("failed to get mmio device name")?;
        }
        let dev_num = get_device_number(&storage.source, None)?;
        handle_block_storage(ctx.logger, &storage, &dev_num).await
    }
}

#[derive(Debug)]
pub struct VirtioBlkPciHandler {}

#[async_trait::async_trait]
impl StorageHandler for VirtioBlkPciHandler {
    #[instrument]
    fn driver_types(&self) -> &[&str] {
        &[DRIVER_BLK_PCI_TYPE]
    }

    #[instrument]
    async fn create_device(
        &self,
        mut storage: Storage,
        ctx: &mut StorageContext,
    ) -> Result<Arc<dyn StorageDevice>> {
        let dev_num: String;

        // If hot-plugged, get the device node path based on the PCI path
        // otherwise use the virt path provided in Storage Source
        if storage.source.starts_with("/dev") {
            let metadata = fs::metadata(&storage.source)
                .context(format!("get metadata on file {:?}", &storage.source))?;
            let mode = metadata.permissions().mode();
            if mode & libc::S_IFBLK == 0 {
                return Err(anyhow!("Invalid device {}", &storage.source));
            }
            dev_num = get_device_number(&storage.source, Some(&metadata))?;
        } else {
            let (root_complex, pcipath) = pcipath_from_dev_tree_path(&storage.source)?;
            let dev_path =
                get_virtio_blk_pci_device_name(ctx.sandbox, root_complex, &pcipath).await?;
            storage.source = dev_path;
            dev_num = get_device_number(&storage.source, None)?;
        }

        handle_block_storage(ctx.logger, &storage, &dev_num).await
    }
}

#[cfg(target_arch = "s390x")]
#[derive(Debug)]
pub struct VirtioBlkCcwHandler {}

#[cfg(target_arch = "s390x")]
#[async_trait::async_trait]
impl StorageHandler for VirtioBlkCcwHandler {
    #[instrument]
    fn driver_types(&self) -> &[&str] {
        &[DRIVER_BLK_CCW_TYPE]
    }

    #[cfg(target_arch = "s390x")]
    #[instrument]
    async fn create_device(
        &self,
        mut storage: Storage,
        ctx: &mut StorageContext,
    ) -> Result<Arc<dyn StorageDevice>> {
        let ccw_device = ccw::Device::from_str(&storage.source)?;
        let dev_path = get_virtio_blk_ccw_device_name(ctx.sandbox, &ccw_device).await?;
        storage.source = dev_path;
        let dev_num = get_device_number(&storage.source, None)?;
        handle_block_storage(ctx.logger, &storage, &dev_num).await
    }

    #[cfg(not(target_arch = "s390x"))]
    #[instrument]
    async fn create_device(
        &self,
        _storage: Storage,
        _ctx: &mut StorageContext,
    ) -> Result<Arc<dyn StorageDevice>> {
        Err(anyhow!("CCW is only supported on s390x"))
    }
}

#[derive(Debug)]
pub struct ScsiHandler {}

#[async_trait::async_trait]
impl StorageHandler for ScsiHandler {
    #[instrument]
    fn driver_types(&self) -> &[&str] {
        &[DRIVER_SCSI_TYPE]
    }

    #[instrument]
    async fn create_device(
        &self,
        mut storage: Storage,
        ctx: &mut StorageContext,
    ) -> Result<Arc<dyn StorageDevice>> {
        // Retrieve the device path from SCSI address.
        let dev_path = get_scsi_device_name(ctx.sandbox, &storage.source).await?;
        storage.source = dev_path.clone();

        let dev_num = get_device_number(&dev_path, None)?;
        handle_block_storage(ctx.logger, &storage, &dev_num).await
    }
}

#[derive(Debug)]
pub struct PmemHandler {}

#[async_trait::async_trait]
impl StorageHandler for PmemHandler {
    #[instrument]
    fn driver_types(&self) -> &[&str] {
        &[DRIVER_NVDIMM_TYPE]
    }

    #[instrument]
    async fn create_device(
        &self,
        storage: Storage,
        ctx: &mut StorageContext,
    ) -> Result<Arc<dyn StorageDevice>> {
        // Retrieve the device for pmem storage
        wait_for_pmem_device(ctx.sandbox, &storage.source).await?;

        let path = common_storage_handler(ctx.logger, &storage)?;
        new_device(path)
    }
}
