#!/usr/bin/python3

import asyncio
import logging
import signal
import pulsectl
from usb.core import find, USBTimeoutError, USBError
import logging.handlers
import argparse
from datetime import time

arg_parser = argparse.ArgumentParser()
arg_parser.add_argument("--log-dir", type=str, default="./")
arg_parser.add_argument("--log-level", type=str, default="INFO")
arg_parser.add_argument("--verbose", type=bool, default=False)
arg_parser.add_argument("--use-syslog", type=bool, default=False)

args = arg_parser.parse_args()
log_dir = args.log_dir
log_level = args.log_level
log_verbose = args.verbose
use_syslog = args.use_syslog

def setup_logging():
    """Sets up logging to file, syslog, and console."""
    logger = logging.getLogger()
    logger.setLevel(log_level)

    if use_syslog:
        # Add syslog handler
        syslog_handler = logging.handlers.SysLogHandler(address='/dev/log')
        syslog_handler.setFormatter(
            logging.Formatter('nova_control[%(process)d]: %(levelname)s %(message)s')
        )
        logger.addHandler(syslog_handler)

    # Add rotating file handler
    file_handler = logging.handlers.RotatingFileHandler(
        f'{log_dir}nova_control.log',
        maxBytes=1024*1024,  # 1MB
        backupCount=5
    )
    file_handler.setFormatter(
        logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    )
    logger.addHandler(file_handler)

    if log_verbose:
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(
            logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        )
        logger.addHandler(console_handler)
    


setup_logging()


class NovaProWireless:
    """Handles USB communication and PipeWire integration for SteelSeries Arctis Nova Pro Wireless."""

    VID = 0x1038
    PID = 0x12E5
    INTERFACE = 0x4
    ENDPOINT_TX = 0x4  # EP 4 OUT
    ENDPOINT_RX = 0x84  # EP 4 IN
    MSGLEN = 64  # USB packet: 128 bytes total, last 64 bytes for data.

    # Control codes
    TX = 0x6  # To base station
    RX = 0x7  # From base station
    OPT_SONAR_ICON = 141
    OPT_CHATMIX_ENABLE = 73
    OPT_VOLUME = 37
    OPT_CHATMIX = 69
    OPT_EQ = 49
    OPT_EQ_PRESET = 46

    # PipeWire Virtual Devices
    PW_ORIGINAL_SINK: str | None = None
    PW_GAME_SINK = "NovaGame"
    PW_CHAT_SINK = "NovaChat"

    def __init__(self):

        max_retries = 3
        retry_delay = 2
        for attempt in range(max_retries):
            try:
                self.dev = find(idVendor=self.VID, idProduct=self.PID)
                if self.dev is None:
                    raise ValueError("Device not found")
                if self.dev.is_kernel_driver_active(self.INTERFACE):
                    self.dev.detach_kernel_driver(self.INTERFACE)
                break
            except (USBError, ValueError) as e:
                if attempt == max_retries - 1:
                    raise
                logging.warning(f"Attempt {attempt + 1} failed: {e}. Retrying in {retry_delay}s...")
                time.sleep(retry_delay)
            
        # Initialize PulseAudio/PipeWire connection
        self.pulse = pulsectl.Pulse('nova-control')
        
        if self.dev.is_kernel_driver_active(self.INTERFACE):
            self.dev.detach_kernel_driver(self.INTERFACE)

        self._shutdown_event = asyncio.Event()

    def _create_msgdata(self, data: tuple[int, ...]) -> bytes:
        """

        """
        return bytes(data).ljust(self.MSGLEN, b"0")

    async def set_chatmix_controls(self, state: bool):
        """Enable or disable chatmix controls."""
        self.dev.write(self.ENDPOINT_TX, self._create_msgdata((self.TX, self.OPT_CHATMIX_ENABLE, int(state))))

    async def set_sonar_icon(self, state: bool):
        """Enable or disable Sonar Icon."""
        self.dev.write(self.ENDPOINT_TX, self._create_msgdata((self.TX, self.OPT_SONAR_ICON, int(state))))


    async def _create_virtual_sink(self, name: str):
        """Creates a virtual sink using pulsectl."""
        # First create a null sink
        sink_args = f'sink_name={name} sink_properties=device.description="{name}"'
        sink_id = self.pulse.module_load('module-null-sink', sink_args)
        
        # Then create a loopback from this sink to the headset
        loopback_args = (
            f'source="{name}.monitor" '
            f'sink="{self.PW_ORIGINAL_SINK}" '
            f'source_dont_move=true '
            f'sink_dont_move=true'
        )
        loopback_id = self.pulse.module_load('module-loopback', loopback_args)
        
        return (sink_id, loopback_id)

    async def _detect_original_sink(self):
        """Detects the original PipeWire sink using pulsectl."""
        if self.PW_ORIGINAL_SINK:
            return

        for sink in self.pulse.sink_list():
            if "SteelSeries_Arctis_Nova_Pro_Wireless" in sink.name:
                self.PW_ORIGINAL_SINK = sink.name
                logging.info(f"Detected sink: {self.PW_ORIGINAL_SINK}")
                break

    async def _start_virtual_sinks(self):
        """Creates virtual sinks using pulsectl."""
        await self._detect_original_sink()
        if not self.PW_ORIGINAL_SINK:
            logging.error("Original sink not found, cannot create virtual sinks.")
            return

        self.game_module_ids = await self._create_virtual_sink(self.PW_GAME_SINK)
        self.chat_module_ids = await self._create_virtual_sink(self.PW_CHAT_SINK)
        logging.info("Virtual sinks started.")


    async def _remove_virtual_sinks(self):
        """Stops virtual sinks."""
        try:
            if hasattr(self, 'game_module_ids'):
                sink_id, loopback_id = self.game_module_ids
                self.pulse.module_unload(sink_id)
                self.pulse.module_unload(loopback_id)
            if hasattr(self, 'chat_module_ids'):
                sink_id, loopback_id = self.chat_module_ids
                self.pulse.module_unload(sink_id)
                self.pulse.module_unload(loopback_id)
            logging.info("Virtual sinks removed.")
        except Exception as e:
            logging.error(f"Error removing virtual sinks: {e}")

    async def _set_sink_volume(self, sink_name: str, volume: int):
        """Sets volume for a sink using pulsectl."""
        try:
            volume_value = volume / 100.0  # Convert percentage to float
            for sink in self.pulse.sink_list():
                if sink.name == sink_name:  # Look for exact sink name match
                    self.pulse.volume_set_all_chans(sink, volume_value)
                    logging.debug(f"Set volume for {sink_name} to {volume}%")
                    break
            else:
                logging.warning(f"Sink {sink_name} not found")
        except Exception as e:
            logging.error(f"Error setting volume: {e}")

    async def health_check(self):
        """Verify device connectivity and audio subsystem status."""
        try:
            # Check USB device
            self.dev.ctrl_transfer(0x80, 0x06, 0x0100, 0x0000, 1)
            
            # Check PulseAudio connection
            self.pulse.sink_list()
            
            # Verify virtual sinks exist
            sinks = {sink.name for sink in self.pulse.sink_list()}
            if not (self.PW_GAME_SINK in sinks and self.PW_CHAT_SINK in sinks):
                logging.error("Virtual sinks missing")
                return False
                
            return True
        except Exception as e:
            logging.error(f"Health check failed: {e}")
            return False

    async def chatmix(self):
        """Continuously reads ChatMix messages and adjusts volumes with recovery."""
        recovery_delay = 5
        while not self._shutdown_event.is_set():
            try:
                await self._start_virtual_sinks()
                while not self._shutdown_event.is_set():
                    try:
                        msg = await asyncio.get_event_loop().run_in_executor(
                            None, 
                            lambda: self.dev.read(self.ENDPOINT_RX, self.MSGLEN, timeout=100)
                        )
                        
                        if not await self.health_check():
                            raise RuntimeError("Health check failed")
                            
                        if msg[1] != self.OPT_CHATMIX:
                            continue

                        gamevol, chatvol = msg[2], msg[3]
                        await asyncio.gather(
                            self._set_sink_volume(self.PW_GAME_SINK, gamevol),
                            self._set_sink_volume(self.PW_CHAT_SINK, chatvol)
                        )
                        
                    except USBTimeoutError:
                        await asyncio.sleep(0.1)
                        continue
                        
            except Exception as e:
                logging.error(f"Error in chatmix loop: {e}")
                if not self._shutdown_event.is_set():
                    logging.info(f"Attempting recovery in {recovery_delay} seconds...")
                    await asyncio.sleep(recovery_delay)
                    continue
            finally:
                await self._remove_virtual_sinks()

    async def close(self):
        """Handles cleanup on exit."""
        self._shutdown_event.set()
        await self.set_chatmix_controls(False)
        await self.set_sonar_icon(False)
        await self._remove_virtual_sinks()
        self.pulse.close()
        logging.info("Exiting gracefully.")


async def run_nova():
    """Main function with proper signal handling."""
    loop = asyncio.get_running_loop()
    stop_event = asyncio.Event()
    
    async def shutdown(signal_name):
        """Handles SIGINT and SIGTERM."""
        logging.info(f"Received {signal_name}, shutting down...")
        stop_event.set()
    
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(
            sig, 
            lambda s=sig: asyncio.create_task(shutdown(s.name))
        )
    
    try:
        nova = NovaProWireless()
        await nova.set_sonar_icon(True)
        await nova.set_chatmix_controls(True)
        
        chatmix_task = asyncio.create_task(nova.chatmix())
        stop_event_task = asyncio.create_task(stop_event.wait())
        
        # Wait for either the chatmix task to complete or stop_event to be set
        done, pending = await asyncio.wait(
            [chatmix_task, stop_event_task],
            return_when=asyncio.FIRST_COMPLETED
        )
        
        # Cancel any pending tasks
        for task in pending:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
            
    except Exception as e:
        logging.error(f"Error in run_nova: {e}")
        raise
    finally:
        try:
            await nova.close()
        except Exception as e:
            logging.error(f"Error during cleanup: {e}")


def main():
    """Entry point that correctly sets up the event loop and signal handling."""
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    
    try:
        loop.run_until_complete(run_nova())
    except KeyboardInterrupt:
        logging.info("KeyboardInterrupt received, shutting down.")
    except Exception as e:
        logging.error(f"Unexpected error: {e}")
    finally:
        try:
            # Clean up any remaining tasks
            pending = asyncio.all_tasks(loop)
            if pending:
                loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
        finally:
            loop.close()


if __name__ == "__main__":
    main()