// Tier 1: Dedicated surveillance manufacturers — always cameras
const HIKVISION_OUIS = [
  '00BC99','040312','04EECD','083BC1','085411','08A189','08CC81','0C75D2','1012FB',
  '1868CB','188025','240F9B','2428FD','2432AE','244845','2857BE','2CA59C','340962',
  '3C1BF8','40ACBF','4419B6','4447CC','44A642','48785B','4C1F86','4C62DF','4CBD8F',
  '4CF5DC','50E538','548C81','54C415','5803FB','5850ED','5C345B','64DB8B','686DBC',
  '743FC2','80489F','807C62','80BEAF','80F5AE','849459','849A40','88DE39','8C22D2',
  '8CE748','94E1AC','988B0A','989DE5','98DF82','98F112','A0FF0C','A41437','A42902',
  'A44BD9','A4A459','A4D5C2','ACCB51','ACB92F','B4A382','BC2978','BC5E33','BC9B5E',
  'BCAD28','BCBAC2','C0517E','C056E3','C06DED','C42F90','C8A702','D4E853','DC07F8',
  'DCD26A','E0BAAD','E0CA3C','E0DF13','E4D58B','E8A0ED','ECA971','ECC89C','F84DFC',
  'FC9FFD',
];

const EZVIZ_OUIS = [
  '0CA64C','20BBBC','34C6DD','54D60D','588FCF','64244D','64F2FB',
  '78A6A0','78C1AE','94EC13','AC1C26','EC97E0','F47018',
];

const DAHUA_OUIS = [
  '08EDED','14A78B','24526A','30DDAA','38AF29','3CE36B','3CEF8C','407AA4','4C11BF',
  '4C99E8','5CF51A','64FD29','6C1C71','74C929','8CE9B4','9002A9','98F9CC','9C1463',
  'A0BD1D','A8CA87','B44C3B','BC325F','C0395A','C4AAC4','D4430E','E02EFE','E0508B',
  'E4246C','F4B1C2','F8CE07','FC5F49','FCB69D',
];

const AMCREST_OUIS = ['00651E', '9C8ECD', 'A06032'];
const UNIVIEW_OUIS = ['48EA63', '6CF17E', '88263F', 'C47905'];
const AXIS_OUIS = ['00408C', 'ACCC8E', 'B8A44F', 'E82725'];
const REOLINK_OUIS = ['EC71DB'];
const PRAMA_OUIS = ['24B105'];

// Tier 2: Consumer camera brands
const WYZE_OUIS = ['2CAA8E', '7C78B2', '80482C', 'D03F27', 'F0C88B'];
const BLINK_OUIS = ['3CA070', '70AD43', '74AB93', 'F074C1'];
const ARLO_OUIS = ['486264', 'A41162', 'FC9C98'];
const NEST_OUIS = ['18B430', '641666'];
const FOSCAM_OUIS = ['C0562D', 'C8D719', '008E10', 'E0B9E5', '001EF2'];
const YI_XIAOMI_OUIS = ['78025E', '7811DC', '34CE00', '04CF8C', '28D127', '58A60B', '641327'];
const EUFY_OUIS = ['98F1B1', '78C57D', '8CEEA7'];

// Build the lookup maps
export const TIER1_OUIS: Record<string, string> = {};
export const TIER2_OUIS: Record<string, string> = {};

function register(map: Record<string, string>, ouis: string[], name: string) {
  for (const oui of ouis) map[oui] = name;
}

register(TIER1_OUIS, HIKVISION_OUIS, 'Hikvision');
register(TIER1_OUIS, EZVIZ_OUIS, 'EZVIZ');
register(TIER1_OUIS, DAHUA_OUIS, 'Dahua');
register(TIER1_OUIS, AMCREST_OUIS, 'Amcrest');
register(TIER1_OUIS, UNIVIEW_OUIS, 'Uniview');
register(TIER1_OUIS, AXIS_OUIS, 'Axis');
register(TIER1_OUIS, REOLINK_OUIS, 'Reolink');
register(TIER1_OUIS, PRAMA_OUIS, 'Prama Hikvision');

register(TIER2_OUIS, WYZE_OUIS, 'Wyze');
register(TIER2_OUIS, BLINK_OUIS, 'Blink');
register(TIER2_OUIS, ARLO_OUIS, 'Arlo');
register(TIER2_OUIS, NEST_OUIS, 'Nest Labs');
register(TIER2_OUIS, FOSCAM_OUIS, 'Foscam');
register(TIER2_OUIS, YI_XIAOMI_OUIS, 'Yi/Xiaomi');
register(TIER2_OUIS, EUFY_OUIS, 'Eufy');
