"""
NAPALM Brocade/Foundry/Extreme netiron File Transfer

Unfortunately netmiko does not have have native netiron SCP support.  However, the base class BaseFileTransfer
can be extended to support netiron specifics.  The netiron specifics include:
 - netiron command syntax as in many case it differs from IOS syntax
 - netiron error messages are specific to netiron
 - netiron (MLX) only supports merging from slot1 or slot2 and not flash
 - netiron does not provide checksum functions and therefore only file existence and file size comparison are the
   only verifications

Note that it would make sense to maintain this code and it's functionality in netmiko.  However to avoid making Netmiko
change and having another code-base to deal with, I've placed the code here.
"""
import logging
import os
import re
import socket

from netmiko.cisco_base_connection import BaseFileTransfer

logger = logging.getLogger(__name__)

# region Error Classes


class Error(Exception):
    pass


class ScpError(Error):
    """An error occurred while attempting a SCP copy."""


class ScpTimeoutError(ScpError):
    """A device failed to respond to a SCP command within the timeout."""


class ScpMinorError(ScpError):
    """A device reported a SCP minor error."""


class ScpMajorError(ScpError):
    """A device reported a SCP major error."""


class ScpProtocolError(ScpError):
    """An unexpected SCP error occurred."""


class ScpChannelError(ScpError):
    """An error occurred with the SCP channel."""


class ScpClosedError(ScpError):
    """A device closed the SCP connection."""


class SshConfigError(ScpError):
    """The configuration file is either missing or malformed."""


# endregion


class NetironFileTransfer(BaseFileTransfer):
    def __init__(self, ssh_conn, source_file, dest_file, file_system=None, direction="put", timeout=30):
        # call our parent
        super(NetironFileTransfer, self).__init__(ssh_conn, source_file, dest_file, file_system, direction)

        self._timeout = timeout
        self._source_size = 0

    def check_file_exists(self, remote_cmd=""):
        """
        Check if the dest_file already exists on the file system (return boolean).

        Example:
        #dir /slot1/merge_config.txt
        Directory of /slot1/

        06/19/2018 18:52:52                      13 merge_config.txt

                         1 File(s)               13 bytes
                         0 Dir(s)         6,815,744 bytes free

        Args:
            remote_cmd (str): optional command to run
        """
        if self.direction == "put":
            if not remote_cmd:
                remote_cmd = "dir {0}/{1}".format(self.file_system, self.dest_file)
            logger.info("remote_cmd: {}".format(remote_cmd))
            remote_out = self.ssh_ctl_chan.send_command_expect(remote_cmd)
            logger.info("remote_out: {}".format(remote_out))
            if "error: File or pathname not found" in remote_out:
                return False
            elif self.dest_file in remote_out:
                logger.info("file: {} exists".format(self.dest_file))
                return True
            else:
                raise ValueError("Unexpected output from check_file_exists")
        elif self.direction == "get":
            return os.path.exists(self.dest_file)

    def remote_file_size(self, remote_cmd="", remote_file=None):
        """Get the file size of the remote file."""
        if remote_file is None:
            if self.direction == "put":
                remote_file = self.dest_file
            elif self.direction == "get":
                remote_file = self.source_file
        if not remote_cmd:
            remote_cmd = "dir {}/{}".format(self.file_system, remote_file)
        remote_out = self.ssh_ctl_chan.send_command(remote_cmd)

        if "error: File or pathname not found" in remote_out:
            raise IOError("Unable to find file on remote system")

        # Strip out "Directory of flash:/filename line
        remote_out = re.split(r"Directory of .*", remote_out)
        remote_out = "".join(remote_out)

        logger.debug("remote_out: {}".format(remote_out))

        # Match line containing file name
        escape_file_name = re.escape(remote_file)
        pattern = r".*({}).*".format(escape_file_name)
        match = re.search(pattern, remote_out)

        file_size = -1
        if match:
            line = match.group(0)
            # Format will be 26  -rw-   6738  Jul 30 2016 19:49:50 -07:00  filename
            file_size = line.split()[2].replace(",", "")
        return int(file_size)

    def remote_space_available(self, search_pattern=r"\)\s+(.*) bytes free"):
        """
        Return space available on remote device.

        Example Output:
        dir /flash
        Directory of /flash

        06/13/2017 12:40:43                   3,588  $$user_profile
        ...

                        11 File(s)       21,647,581 bytes
                         0 Dir(s)       108,789,760 bytes free
        :param search_pattern:
        :return:
        """
        remote_cmd = "dir {}".format(self.file_system)
        remote_output = self.ssh_ctl_chan.send_command_expect(remote_cmd)

        match = re.search(search_pattern, remote_output)
        return int(match.group(1).replace(",", "")) if match else -1

    def verify_space_available(self, search_pattern=r"\)\s+(.*) bytes free"):
        """Verify sufficient space is available on destination file system (return boolean)."""
        space_avail = 0
        if self.direction == "put":
            space_avail = self.remote_space_available(search_pattern=search_pattern)
        elif self.direction == "get":
            space_avail = self.local_space_available()

        if space_avail > self.file_size:
            return True
        return False

    def enable_scp(self, cmd=None):
        """
        Enable SCP on remote device.
        """
        if cmd is None:
            cmd = ["ip ssh scp enable"]
        elif not hasattr(cmd, "__iter__"):
            cmd = [cmd]
        self.ssh_ctl_chan.send_config_set(cmd)

    def disable_scp(self, cmd=None):
        """
        Disable SCP on remote device.
        """
        if cmd is None:
            cmd = ["ip ssh scp disable"]
        elif not hasattr(cmd, "__iter__"):
            cmd = [cmd]
        self.ssh_ctl_chan.send_config_set(cmd)

    def put_file(self):
        """SCP copy the file from the local system to the remote device."""
        destination = "{}{}".format(self.__class__.__gen_brocade_destination__(self.file_system), self.dest_file)
        logger.info("destination: {}".format(destination))
        if ":" not in destination:
            raise ValueError("Invalid destination file system specified")

        with open(self.source_file) as f:
            _source_data = f.read()

        # logger.info('source data: {}'.format(_source_data))
        self.__class__.__scp_put__(self.scp_conn.get_transport(), _source_data, destination)

        # when testing from a windows system the os.stat(source_file).st_size did NOT match the file size
        # on the brocade device so lets use the payload length
        # todo verify file size calculation on linux
        self._source_size = len(_source_data)

        # self.scp_conn.scp_transfer_file(self.source_file, destination)
        # Must close the SCP connection to get the file written (flush)
        # self.scp_conn.close()

    @staticmethod
    def __gen_brocade_destination__(dest_file_system):
        """
        Generate a brocade specific destination.  Brocade destination will look similar to:
        <brocade device>:flash:/<name of file>
        :return: Brocade specific formatted destination
        """
        return "{}:".format(dest_file_system.replace("/", ""))

    def establish_scp_conn(self):
        """Establish the secure copy connection."""
        ssh_connect_params = self.ssh_ctl_chan._connect_params_dict()
        self.scp_conn = self.ssh_ctl_chan._build_ssh_client()
        self.scp_conn.connect(**ssh_connect_params)
        # self.scp_client = scp.SCPClient(self.scp_conn.get_transport())

    @staticmethod
    def __scp_recv_response(channel):
        """Receives a response on a SCP channel.
        Args:
          channel: A Paramiko channel object.
        Raises:
          ScpClosedError: If the device has closed the connection.
          ScpMajorError: If the device reports a major error.
          ScpMinorError: If the device reports a minor error.
          ScpProtocolError: If an unexpected error occurs.
          ScpTimeoutError: If no response is received within the timeout.
        """
        buf = channel.recv(1)
        while True:
            if channel.recv_stderr_ready():
                # Dodgy: Cisco sometimes *ask* for a password, but they don't actually
                err = channel.recv_stderr(512)
                if err == "Password: ":
                    logging.warn("Password prompt received on SCP stderr, assuming " "IOS bug (ignoring)")
                else:
                    raise ScpProtocolError("Data on stderr: %r" % err)

            if not buf:
                raise ScpClosedError("Connection closed by remote device")

            if buf == "\x00":
                # Code \x00 indicates success.  Brocade have been observed sending
                # \x00\x02 followed by an error message, so we need to only read
                # the single \x00 and leave the error message to be handled in a
                # future call to __scp_recv_response.
                return

            try:
                extra = channel.recv(512)
                if not extra:
                    raise ScpProtocolError("Connection closed by remote device; partial response: %r" % buf)
                else:
                    buf += extra
            except socket.timeout:
                if buf:
                    raise ScpProtocolError("Timed out reading from socket; partial response: %r" % buf)
                else:
                    raise ScpTimeoutError("Timed out reading from socket")

            if buf[-1] == "\n":
                if buf[0] == "\x01":
                    if buf.startswith("\x01File ") and buf.rstrip().endswith("created successfully."):
                        return
                    raise ScpMinorError(buf[1:-1])
                elif buf[0] == "\x02":
                    # Code \x02: Fatal error.
                    raise ScpMajorError(buf[1:-1])
                else:
                    # Default case: Fatal error.
                    raise ScpMajorError(buf[:-1])

    @staticmethod
    def __scp_put__(transport, source_data, destination_file, timeout=20, send_buffer=8192):
        """Puts a file via SCP protocol.
        Args:
          transport: A Paramiko transport object.
          source_data: The source data to copy as a string.
          destination_file: The file on the remote device.
          timeout: The timeout to use for the SCP channel.
          send_buffer: The number of bytes to send in each operation.
        Raises:
          ConnectionError: There was an error trying to start the SCP connection.
          ScpError: There was an error copying the file.
        """
        channel = transport.open_session()
        try:
            channel.settimeout(timeout)
            channel.exec_command("scp -t %s" % destination_file)

            # Server must acknowledge our connection.
            NetironFileTransfer.__scp_recv_response(channel)

            # Send file attributes, length and a dummy source file basename.
            source_size = len(source_data)
            logger.info("source_size: {}".format(source_size))
            channel.sendall("C0644 %d 1\n" % source_size)

            # Server must acknowledge our request to send.
            NetironFileTransfer.__scp_recv_response(channel)

            # Send the data in chunks rather than all at once
            pos = 0
            while pos < source_size:
                print("pos: {}".format(pos))
                channel.sendall(source_data[pos : pos + send_buffer])
                pos += send_buffer

            # Indicate that we experienced no errors while sending.
            channel.sendall("\0")

            # Get the final status back from the device.  Note: Force10 actually sends
            # final status prior to getting the "all OK" from us.
            NetironFileTransfer.__scp_recv_response(channel)
        finally:
            try:
                channel.close()
            except EOFError:
                raise ScpChannelError("Error closing SCP channel")

    def verify_file(self):
        _remote_file_size = self.remote_file_size()
        logger.info("candidate file size: {0}:{1}".format(_remote_file_size, self._source_size))
        return True if _remote_file_size == self._source_size else False
