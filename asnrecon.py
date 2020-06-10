#https://github.com/orlyjamie

from OpenSSL.crypto import FILETYPE_PEM, load_certificate
from os import listdir, makedirs, remove, system
from shutil import rmtree
from socket import gaierror, gethostbyname, setdefaulttimeout
from ssl import get_server_certificate, socket_error
from threading import Lock, Thread
from traceback import format_exc


# noinspection SpellCheckingInspection
ASNDB_FILE_NAME = 'rib.dat'
BLACKLIST_FILE_NAME = 'main.config'
DEFAULT_SOCKET_TIMEOUT = 5  # seconds
NUMBER_OF_THREADS = 50  # FIXME edit this if you want to change the number of threads the script uses
TMP_DIR_NAME = './temp'
USE_CURL = True  # if set to True then uses curl to get cert info


class IPPool(object):
    """ The class that holds and manages the given ip pool. """

    def __init__(self, *ip_ranges):
        assert len(ip_ranges) > 0, 'List of ip ranges is empty.'

        self.lock = Lock()
        self._ip_ranges = list(ip_ranges)
        self._ip_ranges_info = {}

        for ip_range in self._ip_ranges:
            base_ip, mask = ip_range.split('/')
            mask = int(mask)

            self._ip_ranges_info[ip_range] = {'base_ip_parts': map(int, base_ip.split('.')),
                                              'caption': ip_range,
                                              'filename': '%s(%d)_domains.txt' % (base_ip, mask),
                                              'length': 2 ** (32 - mask)}

        self._current_element_in_range = 1
        self._current_ip_range = 0
        self._exhausted = False

    def get_next_ip(self):
        """ Thread-safe method. Use it for override in sub-class. """
        with self.lock:
            return self._get_next_ip()

    def _get_next_ip(self):
        """ Thread-unsafe method to get next ip of range. Returns dict with ip info or None if exhausted. """
        if self._exhausted is False:
            # 1. fetching current ip info (all data are set up from the previous time)
            ip_range = self._ip_ranges[self._current_ip_range]
            ip_range_info = self._ip_ranges_info[ip_range]
            result = {'caption': ip_range_info['caption'] if self._current_element_in_range == 1 else None,
                      'filename': ip_range_info['filename'],
                      'ip': [ip_range_info['base_ip_parts'][j] +
                             (self._current_element_in_range // 256 ** (3 - j)) % 256
                             for j in range(4)]}

            # 2. setting up data for the next fetch
            self._current_element_in_range += 1  # moving to the next one
            if self._current_element_in_range % 256 == 0:  # ips like x.x.x.0 are omitted for they are not valid
                self._current_element_in_range += 1

            if self._current_element_in_range >= ip_range_info['length']:  # current range is exhausted
                self._current_element_in_range = 1
                self._current_ip_range += 1
                if self._current_ip_range >= len(self._ip_ranges):  # all ranges are exhausted
                    self._exhausted = True

            # 3. actual result
            return result

    def resolve_ip_ranges(self):
        thread_pool = []

        for _ in range(NUMBER_OF_THREADS):
            worker = IPResolverWorker(self, self.lock)
            worker.daemon = True
            worker.start()
            thread_pool.append(worker)

        try:
            [i.join() for i in thread_pool]
        except KeyboardInterrupt:
            print('Terminating...')
        else:
            print('Finished.')


# noinspection SpellCheckingInspection
class IPPoolASN(IPPool):
    """ The class that builds ip pool by the given hostname. """

    def __init__(self, hostname):
        try:
            from pyasn import pyasn
        except ImportError:
            system('pip install pyasn')
            from pyasn import pyasn

        try:
            asndb = pyasn(ASNDB_FILE_NAME)
        except IOError:
            print('File "%s" is missing. Setup? [y/n]' % ASNDB_FILE_NAME)
            if str(raw_input()).strip().lower() == 'y':
                self._install_asndb()
                asndb = pyasn(ASNDB_FILE_NAME)
            else:
                raise RuntimeError('File "%s" not found.' % ASNDB_FILE_NAME)

        try:
            main_ip = gethostbyname(hostname)
        except gaierror:
            raise RuntimeError('Couldn''t get ip for host %s.' % hostname)

        try:
            self._ignored_ranges = []
            with open(BLACKLIST_FILE_NAME, 'r') as f:
                for i in f.read().split(','):
                    ignored_ip_range = i.strip()
                    if ignored_ip_range:
                        self._ignored_ranges.append(self._ip_range_to_range(ignored_ip_range))
        except IOError:
            print('File "%s" is missing, ips will not be ignored.' % BLACKLIST_FILE_NAME)

        ip_ranges = sorted(asndb.get_as_prefixes(asndb.lookup(main_ip)[0]))
        print('Found ranges %s' % ip_ranges)

        super(IPPoolASN, self).__init__(*ip_ranges)

    def get_next_ip(self):
        with self.lock:
            result = self._get_next_ip()
            while result is not None and self._ip_is_ignored(result['ip']):
                result = self._get_next_ip()
            return result

    @staticmethod
    def _install_asndb():
        """ Trying to download and install ASN database. """
        existing_files = set(listdir('.'))
        system('python pyasn_util_download.py --latest')
        rib_file_name = (set(listdir('.')) - existing_files).pop()
        system('python pyasn_util_convert.py --single %s %s' % (rib_file_name, ASNDB_FILE_NAME))
        remove(rib_file_name)

    @staticmethod
    def _ip_range_to_range(ip_range):
        """ Converts ip range with subnet to 2 lists: minimum and maximum ip of the range. """
        base_ip, mask = ip_range.split('/')
        base_ip_parts = map(int, base_ip.split('.'))
        length = 2 ** (32 - int(mask))

        ip1 = [i for i in base_ip_parts]
        ip2 = [base_ip_parts[i] + (length // 256 ** (3 - i)) % 256 for i in range(4)]

        return ip1, ip2

    def _ip_is_ignored(self, ip):
        for ignored_range in self._ignored_ranges:
            if ignored_range[0] <= ip <= ignored_range[1]:
                return True
        return False


class IPResolverWorker(Thread):
    """ Thread that uses ip queue and resolves ip to names. """

    _curl_param_str = '''curl -kvv --connect-timeout %(timeout)d --silent https://%(ip)s 2>&1 | awk 'BEGIN { FS = "CN="} ; {print $2}' | awk 'NF' | awk 'FNR%%2' > %(out_file)s'''
    _use_curl = USE_CURL

    def __init__(self, generator, lock):
        super(IPResolverWorker, self).__init__()
        self.generator = generator
        self.lock = lock

    # noinspection PyBroadException
    def run(self):
        while True:
            try:
                ip_info = self.generator.get_next_ip()
                if ip_info is not None:
                    if ip_info['caption'] is not None:
                        with self.lock:
                            print('Testing %s...' % ip_info['caption'])

                    ip = '.'.join(str(i) for i in ip_info['ip'])
                    resolved = self.resolve_name_for_ip(ip)

                    if resolved:
                        with open(ip_info['filename'], 'a+') as f, self.lock:
                            f.write('https://%s - %s\n' % (ip, resolved))
                            f.flush()

                            print('[*] Domain found - https://%s - %s' % (ip, resolved))
                else:
                    return
            except:
                print(format_exc())

    def resolve_name_for_ip(self, ip):
        """ Trying to resolve hostname for the given ip. Returns resolved name or nothing if couldn't. """
        if self._use_curl:
            # sick way to get server certificate
            out_file_name = '%s/%d' % (TMP_DIR_NAME, self.ident)
            system(self._curl_param_str % {'ip': ip,
                                           'out_file': out_file_name,
                                           'timeout': DEFAULT_SOCKET_TIMEOUT})

            with open(out_file_name, 'r') as f:
                content = f.read().strip()
                if content:
                    return content.split(';')[0]
        else:
            # usual way to get server certificate
            try:
                pem = get_server_certificate((ip, 443))
            except socket_error:
                pass
            else:
                if pem:
                    for cid, val in load_certificate(FILETYPE_PEM, pem).get_subject().get_components():
                        if cid == 'CN':
                            return val


if __name__ == '__main__':
    setdefaulttimeout(DEFAULT_SOCKET_TIMEOUT)

    # noinspection PyBroadException
    try:
        makedirs(TMP_DIR_NAME)

        print('Select an option:\n\t[1] Full ASN scan\n\t[2] Specific IPv4 range scan')
        selected = str(raw_input()).strip()

        if selected == '1':
            arg = str(raw_input('Please input the host name: ')).strip()
            cls = IPPoolASN
        elif selected == '2':
            arg = str(raw_input('Please input the ip range (like 104.36.195.0/24): ')).strip()
            cls = IPPool
        else:
            raise RuntimeError('Unknown option: "%s".' % selected)

        cls(arg).resolve_ip_ranges()
    except RuntimeError as e:
        print(e.message)
    except SystemExit:
        pass
    except:
        print(format_exc())
    finally:
        rmtree(TMP_DIR_NAME, ignore_errors=True)
