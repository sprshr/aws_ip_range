import ipaddress
import requests
from datetime import datetime

class AWSIPRangeFetchError(Exception):
    def __init__(self, message):
        self.message = message
        super().__init__(self.message)

class AWSIPAddrInvalidError(Exception):
    def __init__(self, message):
        self.message = message
        super().__init__(self.message)

class AWSRegionDoesNotExistError(Exception):
    def __init__(self, message):
        self.message = message
        super().__init__(self.message)

class AbstractAWSIPPrefix:
    """
    Abstract AWS IP Prefix class
    Needs to be inherited by another class that handles IP versioning
    """
    def __init__(self, *args, region: str, service: str, network_border_group: str, **kwargs):
        self._service = service
        self._region = region
        self._network_border_group = network_border_group
        super().__init__(*args, **kwargs)

    @property
    def service(self) -> str:
        return self._service

    @property
    def network_border_group(self) -> str:
        return self._network_border_group

    @property
    def region(self) -> str:
        return self._region


class AWSIPv4Prefix(AbstractAWSIPPrefix, ipaddress.IPv4Network):
    def __init__(self, prefix: str, region: str, service: str, network_border_group: str):
        super().__init__(
            prefix,
            region = region,
            service = service,
            network_border_group = network_border_group
        )

class AWSIPv6Prefix(AbstractAWSIPPrefix, ipaddress.IPv6Network):
    def __init__(self, prefix: str, region: str, service: str, network_border_group: str):
        super().__init__(
            prefix,
            region = region,
            service = service,
            network_border_group = network_border_group
        )

class AWSRegion:
    def __init__(self, name):
        self.name = name
        self._ipv4_prefixes = []
        self._ipv6_prefixes = []

    def add_ip_prefix(self, prefix: AWSIPv4Prefix | AWSIPv6Prefix) -> None:
        if prefix.version == 4:
            self._ipv4_prefixes.append(prefix)
            return
        if prefix.version == 6:
            self._ipv6_prefixes.append(prefix)
            return

    def __str__(self):
        return f'Region: {self.name} IPV4: {len(self._ipv4_prefixes)} IPV6: {len(self._ipv6_prefixes)} '

    def __repr__(self):
        return f'AWSRegion(Region: {self.name} IPV4: {len(self._ipv4_prefixes)} IPV6: {len(self._ipv6_prefixes)})'

    def __contains__(self, ip: ipaddress.IPv4Address | ipaddress.IPv6Address | str) -> bool:
        if isinstance(ip, str):
            # if string is provided, turn it into an ip address
            try:
                ip = ipaddress.ip_address(ip)
            except ValueError:
                raise AWSIPAddrInvalidError(f'Invalid IP address {ip}')
        if isinstance(ip, ipaddress.IPv4Address):
            return any(ip in ip_network for ip_network in self._ipv4_prefixes)
        if isinstance(ip, ipaddress.IPv6Address):
            return any(ip in ip_network for ip_network in self._ipv6_prefixes)

        raise TypeError(f'Unsupported type {type(ip)}')

class AWSIpRangeMeta(type):
    """
    Metaclass for AWSIPRange class
    Helps use methods like __contains__, __getitem__ on the class itself
    """

    def _check_data(cls):
        """
        Checks that AWS IP Ranges exists
        If not, it will trigger an update
        :return:
        """
        if not cls._regions:
            cls.update()

    def __contains__(cls, ip: ipaddress.IPv4Address | ipaddress.IPv6Address | str):
        # Check if an IP address belongs to AWS
        cls._check_data()
        for region in cls._regions.values():
            if ip in region:
                return True
        return False

    def __getattr__(cls, item):
        # Return regions as class attributes
        cls._check_data()
        try:
            return cls._regions[item]
        except KeyError:
            raise AWSRegionDoesNotExistError(f'AWS Region {item} does not exist') from None

class AWSIpRange(metaclass=AWSIpRangeMeta):
    """
    Represents the published AWS IP range
    """

    # The current IP Address range is available as a json here
    __current_range_url: str = 'https://ip-ranges.amazonaws.com/ip-ranges.json'

    # Sync token updated everytime the range is updated
    __sync_token: str | None = None

    # Last update (naive)
    __create_date: datetime | None = None

    # AWS regions
    _regions: dict[str, AWSRegion] = {}

    #Add the current IP Address range URL to the docstring
    __doc__ = __doc__ + __current_range_url

    @staticmethod
    def _get_cidr_version(cidr: str) -> int:
        """
        Return the ip version of a CIDR block
        """
        try:
            network = ipaddress.ip_network(cidr)
        except ValueError:
            raise ValueError(f'{cidr} is not a valid CIDR block')

        return network.version

    @classmethod
    def _add_to_regions(cls, ip_network: AWSIPv4Prefix | AWSIPv6Prefix):
        f"""
        Creates an attribute for {cls.__name__} based on the region of a given ip network.
        If the attribute is already present, the ip network will be added to the attribute.
        """

        key_name = ip_network.region.upper().replace('-', '_')

        # Get the attribute for the region
        try:
            region = cls._regions[key_name]
            region.add_ip_prefix(ip_network)
        except KeyError:
            # if region doesn't exist, create it and add it to the regions dict
            region = AWSRegion(ip_network.region)
            region.add_ip_prefix(ip_network)
            cls._regions[key_name] = region

    @classmethod
    def _set_aws_ip_prefix(cls, json_date: dict[str, str | list[dict]]) -> None:
        # IPV4 prefixes
        for prefix in json_date['prefixes']:
            ip_prefix = prefix['ip_prefix']
            region = prefix['region']
            service = prefix['service']
            network_border_group = prefix['network_border_group']
            ip_network = AWSIPv4Prefix(ip_prefix, region, service,network_border_group)
            cls._add_to_regions(ip_network)

        # IPV6 prefixes
        for prefix in json_date['ipv6_prefixes']:
            ip_prefix = prefix['ipv6_prefix']
            region = prefix['region']
            service = prefix['service']
            network_border_group = prefix['network_border_group']
            ip_network = AWSIPv6Prefix(ip_prefix, region, service,network_border_group)
            cls._add_to_regions(ip_network)

    @classmethod
    def update(cls):
        """
        Updates the AWS IP range
        """
        r = requests.get(cls.__current_range_url)

        # Check if the requests was successful
        if r.status_code != requests.codes.ok:
            log_msg = f'Failed to get AWS IP range with status code {r.status_code}'
            raise AWSIPRangeFetchError(log_msg)

        # get the json payload
        json_data = r.json()

        # get sync_token and create_date
        sync_token = json_data['syncToken']
        create_date: str = json_data['createDate']

        # Update sync token and createDate
        cls.__sync_token = sync_token
        cls.__create_date = datetime.strptime(create_date, '%Y-%m-%d-%H-%M-%S')

        cls._set_aws_ip_prefix(json_data)
