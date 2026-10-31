/** Device-type profiles: one pick fills the on-connect commands and the
 *  config-capture command with the right defaults for a platform, instead of
 *  setting each field by hand. Applied in the host editor; not stored on the
 *  host (the resulting commands are).
 */
export interface DeviceProfile {
  id: string
  label: string
  startupCommands: string[]
  configCommand: string
}

export const DEVICE_PROFILES: DeviceProfile[] = [
  {
    id: 'panos',
    label: 'Palo Alto (PAN-OS)',
    startupCommands: ['set cli terminal width 200', 'set cli pager off'],
    configCommand: 'show config running',
  },
  {
    id: 'ios',
    label: 'Cisco IOS / NX-OS',
    startupCommands: ['terminal length 0'],
    configCommand: 'show running-config',
  },
  {
    id: 'junos',
    label: 'Juniper Junos',
    startupCommands: ['set cli screen-length 0', 'set cli screen-width 200'],
    configCommand: 'show configuration | display set',
  },
  {
    id: 'linux',
    label: 'Linux (tmux)',
    startupCommands: ['tmux new-session -A -D -s hawser-{pane}'],
    configCommand: 'cat /etc/os-release',
  },
]
