from trezor import wire
from trezor.messages.Success import Success

from apps.common import mnemonic, storage
from apps.management.reset_device import backup_seed, layout


async def backup_device(ctx, msg):
    if not storage.is_initialized():
        raise wire.ProcessError("Device is not initialized")
    if not storage.device.needs_backup():
        raise wire.ProcessError("Seed already backed up")

    mnemonic_secret, mnemonic_type = mnemonic.get()

    storage.device.set_unfinished_backup(True)
    storage.device.set_backed_up()

    await backup_seed(ctx, mnemonic_type, mnemonic_secret)

    storage.device.set_unfinished_backup(False)

    await layout.show_backup_success(ctx)

    return Success(message="Seed successfully backed up")
