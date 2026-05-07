// Project Aether · disaster-response taxonomy.
//
// Single source of truth for:
//   - AGENCIES         every body legally empowered (or operationally
//                      tasked) to respond to a disaster in India
//   - UNIT_TYPES       the resource taxonomy a dispatcher allocates
//   - UNIT_CATEGORIES  high-level capability buckets used by the DSS
//                      and the cross-agency mutual-aid graph
//   - INTER_AGENCY     mutual-aid edges: which agencies can task /
//                      request from / report to which others
//
// Statutory references in the codes:
//   DM Act 2005 ss. 6, 14, 25, 35     NDMA / SDMA / DDMA / NGOs
//   IS 14458                          rockfall barrier specs
//   AFSPA / MoD AID-1                 Armed Forces Aid to Civil Authority
//   IT Act 2000 s. 79                 Aether intermediary status
//   DPDPA 2023                        Data minimisation + retention
//
// Adding a new agency or unit type is additive: extend the constants
// here, redeploy, the dispatcher renders the new option immediately. No
// schema migration required. The client mirrors the unit-type subset it
// needs into web/tm/tm.js (UNIT_LABEL) so the SPA bundle stays small.

// ---------- Tier ladder (mirrors users.TIER) ----------
//
// Numeric authority that the scope_path prefix RBAC enforces. A higher
// tier reads, edits, and delegates anyone whose scope_path is a prefix
// of their own.
export const COMMAND_TIERS = Object.freeze({
  ndma:           100,  // National Disaster Management Authority (PM-chaired)
  national_ops:    90,  // NDMA Secretariat, NDRF DG, MHA NDM Division
  sdma:            80,  // State Disaster Management Authority (CM-chaired)
  state_ops:       70,  // State EOC, SDRF DG, state cabinet-level ops
  ddma:            60,  // District Disaster Management Authority (DC/DM)
  district_ops:    50,  // ADM (Disaster), district control room
  subdivisional:   40,  // Sub-Divisional Magistrate
  tehsil:          30,  // Tehsildar, Block Development Officer
  volunteer:       20,  // Civil Defence, Aapda Mitra, NCC, NSS, IRCS
  survivor:        10   // Anonymous distress source
});

// ---------- Agencies (the universe of responders) ----------
//
// Each entry: {code, name, level, parent, statute, mandate, contactable}.
//   level     national | state | district | local | facility | utility
//   parent    code of supervisory agency (or null)
//   statute   short reference to the legal basis
//   mandate   one-line description of operational role
// `contactable: true` means the dispatcher UI can route a dispatch to
// this agency (it has a known intake channel). `false` is a reference
// node only.

export const AGENCIES = Object.freeze({
  // === National authority ===
  ndma:           { code: 'ndma',     name: 'National Disaster Management Authority',          level: 'national', parent: 'pmo',    statute: 'DM Act 2005 s.3',   mandate: 'Apex national policy and coordination body, PM-chaired.', contactable: true },
  pmo:            { code: 'pmo',      name: 'Prime Minister\'s Office',                        level: 'national', parent: null,     statute: 'Const. of India',    mandate: 'Cabinet-level escalation when NDMA invokes national emergency.', contactable: true },
  mha_ndm:        { code: 'mha_ndm',  name: 'Ministry of Home Affairs · NDM Division',         level: 'national', parent: 'mha',    statute: 'DM Act 2005 s.6(2)', mandate: 'Inter-state coordination and CAPF tasking for disasters.', contactable: true },
  mha:            { code: 'mha',      name: 'Ministry of Home Affairs',                        level: 'national', parent: 'pmo',    statute: 'Const. of India',    mandate: 'Internal security; commands CAPFs.', contactable: false },
  nec:            { code: 'nec',      name: 'National Executive Committee (DM)',               level: 'national', parent: 'mha_ndm',statute: 'DM Act 2005 s.8',    mandate: 'Operational arm of NDMA, secretary-level.', contactable: true },
  ndrf:           { code: 'ndrf',     name: 'National Disaster Response Force',                level: 'national', parent: 'mha_ndm',statute: 'DM Act 2005 s.44',   mandate: '16 specialist battalions for SAR across hazard types.', contactable: true },
  nidm:           { code: 'nidm',     name: 'National Institute of Disaster Management',       level: 'national', parent: 'ndma',   statute: 'DM Act 2005 s.42',   mandate: 'Training, research, capacity-building.', contactable: false },
  // National scientific / forecasting agencies
  imd:            { code: 'imd',      name: 'India Meteorological Department',                 level: 'national', parent: 'moes',   statute: 'IMD Act 1875',       mandate: 'Cyclone, monsoon, severe weather warnings.', contactable: true },
  cwc:            { code: 'cwc',      name: 'Central Water Commission',                        level: 'national', parent: 'mojshakti', statute: 'Resolution 1945', mandate: 'Flood forecasting, dam safety.', contactable: true },
  gsi:            { code: 'gsi',      name: 'Geological Survey of India',                      level: 'national', parent: 'momin',  statute: 'Resolution 1851',    mandate: 'Earthquake / landslide assessment.', contactable: true },
  incois:         { code: 'incois',   name: 'Indian National Centre for Ocean Information Services', level: 'national', parent: 'moes', statute: 'Resolution 1999', mandate: 'Tsunami warning, storm-surge forecasts.', contactable: true },
  isro:           { code: 'isro',     name: 'Indian Space Research Organisation',              level: 'national', parent: 'dos',    statute: 'ISRO Act 1969',      mandate: 'Satellite imagery, telemetry, comms relay.', contactable: true },
  // === Armed forces (Aid to Civil Authority under MoD) ===
  mod:            { code: 'mod',      name: 'Ministry of Defence',                             level: 'national', parent: 'pmo',    statute: 'Const. of India',    mandate: 'Authorises Aid to Civil Authority deployments.', contactable: true },
  army:           { code: 'army',     name: 'Indian Army',                                     level: 'national', parent: 'mod',    statute: 'Army Act 1950',      mandate: 'Engineers, infantry, signals for major HADR.', contactable: true },
  navy:           { code: 'navy',     name: 'Indian Navy',                                     level: 'national', parent: 'mod',    statute: 'Navy Act 1957',      mandate: 'Coastal, riverine, offshore SAR.', contactable: true },
  iaf:            { code: 'iaf',      name: 'Indian Air Force',                                level: 'national', parent: 'mod',    statute: 'AF Act 1950',        mandate: 'Rotary-wing rescue, supply drops, casevac.', contactable: true },
  coast_guard:    { code: 'coast_guard', name: 'Indian Coast Guard',                           level: 'national', parent: 'mod',    statute: 'Coast Guard Act 1978', mandate: 'Maritime SAR, oil-spill response.', contactable: true },
  // === Central Armed Police Forces (operate cross-state under MHA) ===
  crpf:           { code: 'crpf',     name: 'Central Reserve Police Force',                    level: 'national', parent: 'mha',    statute: 'CRPF Act 1949',      mandate: 'Civil unrest in disaster-affected zones.', contactable: true },
  bsf:            { code: 'bsf',      name: 'Border Security Force',                           level: 'national', parent: 'mha',    statute: 'BSF Act 1968',       mandate: 'Border-area disasters; water wing.', contactable: true },
  itbp:           { code: 'itbp',     name: 'Indo-Tibetan Border Police',                      level: 'national', parent: 'mha',    statute: 'ITBP Act 1992',      mandate: 'High-altitude / Himalayan SAR specialists.', contactable: true },
  ssb:            { code: 'ssb',      name: 'Sashastra Seema Bal',                             level: 'national', parent: 'mha',    statute: 'SSB Act 2007',       mandate: 'Indo-Nepal/Bhutan border, hill rescues.', contactable: true },
  cisf:           { code: 'cisf',     name: 'Central Industrial Security Force',               level: 'national', parent: 'mha',    statute: 'CISF Act 1968',      mandate: 'Industrial-disaster on-site; airports/PSUs.', contactable: true },
  assam_rifles:   { code: 'assam_rifles', name: 'Assam Rifles',                                level: 'national', parent: 'mha',    statute: 'AR Act 2006',        mandate: 'NE region rescue, civil unrest.', contactable: true },

  // === State authority (per state — instance these per scope) ===
  sdma:           { code: 'sdma',     name: 'State Disaster Management Authority',             level: 'state',    parent: 'ndma',   statute: 'DM Act 2005 s.14',   mandate: 'CM-chaired apex state body.', contactable: true },
  sec:            { code: 'sec',      name: 'State Executive Committee (DM)',                  level: 'state',    parent: 'sdma',   statute: 'DM Act 2005 s.20',   mandate: 'Chief Secretary-led ops arm of SDMA.', contactable: true },
  sdrf:           { code: 'sdrf',     name: 'State Disaster Response Force',                   level: 'state',    parent: 'sec',    statute: 'DM Act 2005 s.45',   mandate: 'State-raised specialist SAR.', contactable: true },
  state_eoc:      { code: 'state_eoc', name: 'State Emergency Operations Centre',              level: 'state',    parent: 'sec',    statute: 'NDMA Guidelines 2010', mandate: '24×7 incident-command nerve centre.', contactable: true },
  state_police:   { code: 'state_police', name: 'State Police (DGP)',                          level: 'state',    parent: 'sec',    statute: 'Police Act 1861',    mandate: 'Law and order, traffic, evacuation security.', contactable: true },
  state_fire:     { code: 'state_fire', name: 'State Fire & Emergency Services',               level: 'state',    parent: 'sec',    statute: 'F&ES Acts (state)',  mandate: 'Fire, rescue, building collapse first response.', contactable: true },
  state_health:   { code: 'state_health', name: 'State Health Department',                     level: 'state',    parent: 'sec',    statute: 'Public Health Acts', mandate: 'Hospital surge, blood banks, mass-casualty.', contactable: true },
  state_pwd:      { code: 'state_pwd', name: 'State Public Works Department',                  level: 'state',    parent: 'sec',    statute: 'PWD Manuals',        mandate: 'Road / bridge restoration.', contactable: true },
  state_discom:   { code: 'state_discom', name: 'State Power Distribution Company',            level: 'state',    parent: 'sec',    statute: 'Electricity Act 2003', mandate: 'Power restoration; black-start coordination.', contactable: true },
  state_water:    { code: 'state_water', name: 'State Public Health Engg / Water Board',       level: 'state',    parent: 'sec',    statute: 'State Water Acts',   mandate: 'Drinking water restoration; sanitation.', contactable: true },
  state_transport: { code: 'state_transport', name: 'State Transport Corporation',             level: 'state',    parent: 'sec',    statute: 'MV Act 1988',        mandate: 'Mass evacuation by bus.', contactable: true },
  state_forest:   { code: 'state_forest', name: 'State Forest Department',                     level: 'state',    parent: 'sec',    statute: 'Indian Forest Act',  mandate: 'Wildfire, landslide near reserves, animal rescue.', contactable: true },
  sdms:           { code: 'sdms',     name: 'State Institute of Disaster Management',          level: 'state',    parent: 'sdma',   statute: 'NDMA model rules',   mandate: 'State-level training and SOP authoring.', contactable: false },

  // === District authority ===
  ddma:           { code: 'ddma',     name: 'District Disaster Management Authority',          level: 'district', parent: 'sdma',   statute: 'DM Act 2005 s.25',   mandate: 'DC/DM-chaired district body; binding on all dept.', contactable: true },
  district_eoc:   { code: 'district_eoc', name: 'District Emergency Operations Centre',        level: 'district', parent: 'ddma',   statute: 'NDMA Guidelines',    mandate: 'Field control room.', contactable: true },
  district_police: { code: 'district_police', name: 'District Police (SP)',                    level: 'district', parent: 'state_police', statute: 'Police Act 1861', mandate: 'On-ground law and order.', contactable: true },
  district_health: { code: 'district_health', name: 'Civil Surgeon / Chief Medical Officer',   level: 'district', parent: 'state_health', statute: 'Public Health Acts', mandate: 'District-hospital surge, ambulance dispatch.', contactable: true },
  sdm:            { code: 'sdm',      name: 'Sub-Divisional Magistrate',                       level: 'district', parent: 'ddma',   statute: 'CrPC s.21',          mandate: 'Sub-division executive officer.', contactable: true },
  bdo:            { code: 'bdo',      name: 'Block Development Officer',                       level: 'district', parent: 'sdm',    statute: 'Panchayati Raj Acts', mandate: 'Block-level relief distribution.', contactable: true },
  tehsildar:      { code: 'tehsildar', name: 'Tehsildar',                                      level: 'district', parent: 'sdm',    statute: 'Land Revenue Acts',  mandate: 'Tehsil-level revenue + relief.', contactable: true },
  patwari:        { code: 'patwari',  name: 'Patwari / Halka Karmchari',                       level: 'local',    parent: 'tehsildar', statute: 'Land Revenue Acts', mandate: 'Village-level damage assessment.', contactable: true },

  // === Local / municipal ===
  municipal:      { code: 'municipal', name: 'Municipal Corporation / Council',                level: 'local',    parent: 'ddma',   statute: '74th Amendment',     mandate: 'Urban services, debris clearance.', contactable: true },
  panchayat:      { code: 'panchayat', name: 'Gram Panchayat',                                 level: 'local',    parent: 'bdo',    statute: '73rd Amendment',     mandate: 'Village-level last-mile relief.', contactable: true },
  ward_office:    { code: 'ward_office', name: 'Ward Office',                                  level: 'local',    parent: 'municipal', statute: 'Municipal Acts',  mandate: 'Ward-level coordination.', contactable: true },

  // === Facilities ===
  hospital_central: { code: 'hospital_central', name: 'Central Government Hospital (AIIMS / PGI / etc.)', level: 'facility', parent: 'mohfw', statute: 'CGHS Acts', mandate: 'Tertiary care, mass-casualty receivership.', contactable: true },
  hospital_state:   { code: 'hospital_state',   name: 'State Government Hospital',             level: 'facility', parent: 'state_health', statute: 'Public Health Acts', mandate: 'Secondary / tertiary care.', contactable: true },
  hospital_district:{ code: 'hospital_district', name: 'District Hospital',                    level: 'facility', parent: 'district_health', statute: 'Public Health Acts', mandate: 'District-level emergency receivership.', contactable: true },
  hospital_chc:     { code: 'hospital_chc',     name: 'Community Health Centre',               level: 'facility', parent: 'district_health', statute: 'Public Health Acts', mandate: 'Block-level 30-bed first response.', contactable: true },
  hospital_phc:     { code: 'hospital_phc',     name: 'Primary Health Centre',                 level: 'facility', parent: 'district_health', statute: 'Public Health Acts', mandate: 'Sub-block first aid + referral.', contactable: true },
  hospital_private: { code: 'hospital_private', name: 'Private Hospital (with disaster MoU)',  level: 'facility', parent: 'state_health', statute: 'Clinical Establishments Act 2010', mandate: 'Surge capacity under MoU.', contactable: true },
  blood_bank:       { code: 'blood_bank',       name: 'Blood Bank',                            level: 'facility', parent: 'state_health', statute: 'Drugs & Cosmetics Act', mandate: 'Whole blood / components on request.', contactable: true },
  fire_station:     { code: 'fire_station',     name: 'Fire Station',                          level: 'facility', parent: 'state_fire', statute: 'F&ES Acts (state)', mandate: 'First-response fire / rescue cell.', contactable: true },
  police_station:   { code: 'police_station',   name: 'Police Station',                        level: 'facility', parent: 'district_police', statute: 'Police Act 1861', mandate: 'Beat-area first response.', contactable: true },
  ambulance_service:{ code: 'ambulance_service', name: '108 / 102 Ambulance Service',          level: 'facility', parent: 'state_health', statute: 'EMRI / state contracts', mandate: 'Pre-hospital emergency transport.', contactable: true },

  // === Utilities ===
  telecom_op:     { code: 'telecom_op', name: 'Telecom Operator',                              level: 'utility',  parent: 'dot',    statute: 'Telegraph Act 1885 / Telecom Act 2023', mandate: 'Comms restoration, COW deployment.', contactable: true },
  power_op:       { code: 'power_op',  name: 'Power Distribution Operator',                    level: 'utility',  parent: 'state_discom', statute: 'Electricity Act 2003', mandate: 'Crew dispatch, line restoration.', contactable: true },
  water_op:       { code: 'water_op',  name: 'Water Utility Operator',                         level: 'utility',  parent: 'state_water', statute: 'State Water Acts', mandate: 'Tanker dispatch, RO plants.', contactable: true },
  railways:       { code: 'railways',  name: 'Indian Railways',                                level: 'utility',  parent: 'morail', statute: 'Railways Act 1989',  mandate: 'Mass evacuation; relief train.', contactable: true },

  // === Volunteer / civil society (DM Act 2005 s.35) ===
  civil_defence:  { code: 'civil_defence', name: 'Civil Defence Corps',                        level: 'local',    parent: 'mha',    statute: 'Civil Defence Act 1968', mandate: 'Trained volunteers under DC.', contactable: true },
  ircs:           { code: 'ircs',      name: 'Indian Red Cross Society',                       level: 'national', parent: null,     statute: 'IRCS Act 1920',      mandate: 'Relief, blood, first aid.', contactable: true },
  ncc:            { code: 'ncc',       name: 'National Cadet Corps',                           level: 'national', parent: 'mod',    statute: 'NCC Act 1948',       mandate: 'Cadet volunteers; relief camps.', contactable: true },
  nss:            { code: 'nss',       name: 'National Service Scheme',                        level: 'national', parent: 'mysports', statute: 'Resolution 1969',  mandate: 'Student volunteers.', contactable: true },
  scouts_guides:  { code: 'scouts_guides', name: 'Bharat Scouts and Guides',                   level: 'national', parent: null,     statute: 'BSG Act 1950',       mandate: 'Trained youth volunteers.', contactable: true },
  aapda_mitra:    { code: 'aapda_mitra', name: 'Aapda Mitra',                                  level: 'local',    parent: 'sdma',   statute: 'NDMA Scheme 2016',   mandate: 'Trained community volunteers.', contactable: true },
  sphere_india:   { code: 'sphere_india', name: 'Sphere India (NGO consortium)',               level: 'national', parent: null,     statute: 'Society Reg Act',    mandate: 'Inter-NGO coordination.', contactable: true },
  ngo_relief:     { code: 'ngo_relief', name: 'Registered Relief NGO',                         level: 'local',    parent: null,     statute: 'DM Act 2005 s.35',   mandate: 'Last-mile relief, kit distribution.', contactable: true },

  // === Reference parents (not contactable) ===
  moes:           { code: 'moes',     name: 'Ministry of Earth Sciences',                      level: 'national', parent: 'pmo',    statute: 'AR 2006',            mandate: 'Atmosphere/ocean science parent.', contactable: false },
  mojshakti:      { code: 'mojshakti', name: 'Ministry of Jal Shakti',                         level: 'national', parent: 'pmo',    statute: 'AR 1985',            mandate: 'Water-resources parent.', contactable: false },
  momin:          { code: 'momin',    name: 'Ministry of Mines',                               level: 'national', parent: 'pmo',    statute: 'MMDR Act 1957',      mandate: 'Mining / geology parent.', contactable: false },
  dos:            { code: 'dos',      name: 'Department of Space',                             level: 'national', parent: 'pmo',    statute: 'AR 1972',            mandate: 'Space parent.', contactable: false },
  mohfw:          { code: 'mohfw',    name: 'Ministry of Health and Family Welfare',           level: 'national', parent: 'pmo',    statute: 'AR 1947',            mandate: 'Health parent.', contactable: false },
  dot:            { code: 'dot',      name: 'Department of Telecommunications',                level: 'national', parent: 'pmo',    statute: 'Telecom Act 2023',   mandate: 'Telecom parent.', contactable: false },
  morail:         { code: 'morail',   name: 'Ministry of Railways',                            level: 'national', parent: 'pmo',    statute: 'Railways Act 1989',  mandate: 'Railways parent.', contactable: false },
  mysports:       { code: 'mysports', name: 'Ministry of Youth Affairs and Sports',            level: 'national', parent: 'pmo',    statute: 'AR 2000',            mandate: 'Youth/NSS parent.', contactable: false }
});

// ---------- Unit categories (DSS capability buckets) ----------
//
// The DSS suggester uses categories to short-list units that match an
// incident type. e.g. 'flood' triggers categories ['rescue_water',
// 'medical', 'evac_transport', 'comms', 'shelter'].
export const UNIT_CATEGORIES = Object.freeze({
  rescue_general:    'Search & Rescue (general)',
  rescue_water:      'Search & Rescue (water/flood)',
  rescue_high_alt:   'Search & Rescue (high altitude / mountain)',
  rescue_collapse:   'Search & Rescue (collapsed structure)',
  rescue_air:        'Search & Rescue (rotary-wing / fixed-wing)',
  rescue_fire:       'Fire suppression and rescue',
  medical_pre:       'Pre-hospital medical (ambulance)',
  medical_field:     'Field medical / triage / surgery',
  medical_facility:  'Hospital / facility',
  medical_blood:     'Blood / blood-component bank',
  security:          'Law and order / cordon / traffic',
  security_armed:    'Armed support / convoy escort',
  evac_transport:    'Mass-evacuation transport',
  comms:             'Communications restoration / relay',
  power:             'Power restoration',
  water_sanitation:  'Drinking water / sanitation',
  engineering:       'Heavy engineering / debris / bridging',
  logistics:         'Relief logistics / distribution',
  shelter:           'Shelter / relief camp',
  forecasting:       'Forecasting / sensing / mapping',
  command:           'Incident command / EOC',
  civil:             'Civil society / volunteer'
});

// ---------- Unit types (the things a dispatcher allocates) ----------
//
// Each entry: {code, name, short, agency_codes, category, capacity,
// contact_pref}. agency_codes lists the agencies that operate this unit
// type (mutual-aid graph). short is a 3-4 char sigil for table cells
// (the existing UNIT_LABEL on the client).
export const UNIT_TYPES = Object.freeze({
  // Existing types (kept for back-compat with the live demo seed)
  ambulance:           { code: 'ambulance',           name: 'Ambulance (BLS / ALS)',                          short: 'AMB',  agency_codes: ['ambulance_service','district_health','hospital_district'], category: 'medical_pre',     capacity: 4,  contact_pref: ['phone','radio'] },
  fire_engine:         { code: 'fire_engine',         name: 'Fire Engine',                                    short: 'FE',   agency_codes: ['state_fire','fire_station'],                                  category: 'rescue_fire',     capacity: 8,  contact_pref: ['phone','radio'] },
  police:              { code: 'police',              name: 'Police Patrol',                                  short: 'POL',  agency_codes: ['state_police','district_police','police_station'],            category: 'security',        capacity: 4,  contact_pref: ['phone','radio'] },
  sdrf_team:           { code: 'sdrf_team',           name: 'SDRF Team',                                      short: 'SDRF', agency_codes: ['sdrf'],                                                       category: 'rescue_general',  capacity: 8,  contact_pref: ['radio','phone'] },
  medical_team:        { code: 'medical_team',        name: 'Mobile Medical Team',                            short: 'MED',  agency_codes: ['state_health','district_health'],                             category: 'medical_field',   capacity: 4,  contact_pref: ['phone'] },
  drone:               { code: 'drone',               name: 'Drone (UAV)',                                    short: 'DRN',  agency_codes: ['state_police','sdrf','ndrf','iaf'],                           category: 'forecasting',     capacity: 0,  contact_pref: ['data'] },
  helicopter:          { code: 'helicopter',          name: 'Helicopter',                                     short: 'HEL',  agency_codes: ['iaf','navy','coast_guard','state_police'],                    category: 'rescue_air',      capacity: 6,  contact_pref: ['radio'] },
  // National forces
  ndrf_battalion:      { code: 'ndrf_battalion',      name: 'NDRF Specialist Battalion',                      short: 'NDRF', agency_codes: ['ndrf'],                                                       category: 'rescue_general',  capacity: 45, contact_pref: ['radio','phone'] },
  army_engineer:       { code: 'army_engineer',       name: 'Army Engineering Unit',                          short: 'ENGR', agency_codes: ['army'],                                                       category: 'engineering',     capacity: 30, contact_pref: ['radio'] },
  army_infantry:       { code: 'army_infantry',       name: 'Army Infantry (HADR)',                           short: 'INF',  agency_codes: ['army'],                                                       category: 'rescue_general',  capacity: 30, contact_pref: ['radio'] },
  army_signals:        { code: 'army_signals',        name: 'Army Signals (comms)',                           short: 'SIG',  agency_codes: ['army'],                                                       category: 'comms',           capacity: 12, contact_pref: ['radio'] },
  army_medical:        { code: 'army_medical',        name: 'Army Medical Corps Field Hospital',              short: 'AMC',  agency_codes: ['army'],                                                       category: 'medical_field',   capacity: 50, contact_pref: ['radio'] },
  navy_dive:           { code: 'navy_dive',           name: 'Navy Diving Team',                               short: 'DIVE', agency_codes: ['navy'],                                                       category: 'rescue_water',    capacity: 6,  contact_pref: ['radio'] },
  navy_ship:           { code: 'navy_ship',           name: 'Navy Ship (relief)',                             short: 'SHIP', agency_codes: ['navy'],                                                       category: 'evac_transport',  capacity: 200,contact_pref: ['radio'] },
  iaf_helicopter:      { code: 'iaf_helicopter',      name: 'IAF Rotary-wing (Mi-17, ALH, Cheetah)',          short: 'IAFH', agency_codes: ['iaf'],                                                        category: 'rescue_air',      capacity: 24, contact_pref: ['radio'] },
  iaf_transport:       { code: 'iaf_transport',       name: 'IAF Fixed-wing (C-17, C-130, IL-76)',            short: 'IAFT', agency_codes: ['iaf'],                                                        category: 'evac_transport',  capacity: 100,contact_pref: ['radio'] },
  coast_guard_boat:    { code: 'coast_guard_boat',    name: 'Coast Guard Patrol Boat',                        short: 'CGB',  agency_codes: ['coast_guard'],                                                category: 'rescue_water',    capacity: 12, contact_pref: ['radio'] },
  coast_guard_heli:    { code: 'coast_guard_heli',    name: 'Coast Guard Helicopter',                         short: 'CGH',  agency_codes: ['coast_guard'],                                                category: 'rescue_air',      capacity: 6,  contact_pref: ['radio'] },
  // CAPF
  itbp_mountain:       { code: 'itbp_mountain',       name: 'ITBP Mountain Rescue Squad',                     short: 'ITBP', agency_codes: ['itbp'],                                                       category: 'rescue_high_alt', capacity: 12, contact_pref: ['radio'] },
  bsf_water:           { code: 'bsf_water',           name: 'BSF Water Wing',                                 short: 'BSFW', agency_codes: ['bsf'],                                                        category: 'rescue_water',    capacity: 10, contact_pref: ['radio'] },
  crpf_qrt:            { code: 'crpf_qrt',            name: 'CRPF Quick Reaction Team',                       short: 'CRPF', agency_codes: ['crpf'],                                                       category: 'security_armed',  capacity: 12, contact_pref: ['radio'] },
  cisf_industrial:     { code: 'cisf_industrial',     name: 'CISF Industrial-Disaster Cell',                  short: 'CISF', agency_codes: ['cisf'],                                                       category: 'rescue_general',  capacity: 12, contact_pref: ['radio'] },
  // Health / facility
  hospital_csurge:     { code: 'hospital_csurge',     name: 'Central / AIIMS Surge Slot',                     short: 'AIMS', agency_codes: ['hospital_central'],                                           category: 'medical_facility',capacity: 20, contact_pref: ['phone'] },
  hospital_dsurge:     { code: 'hospital_dsurge',     name: 'District Hospital Surge Slot',                   short: 'DH',   agency_codes: ['hospital_district'],                                          category: 'medical_facility',capacity: 30, contact_pref: ['phone'] },
  hospital_chc_slot:   { code: 'hospital_chc_slot',   name: 'Community Health Centre Slot',                   short: 'CHC',  agency_codes: ['hospital_chc'],                                               category: 'medical_facility',capacity: 30, contact_pref: ['phone'] },
  hospital_phc_slot:   { code: 'hospital_phc_slot',   name: 'Primary Health Centre Slot',                     short: 'PHC',  agency_codes: ['hospital_phc'],                                               category: 'medical_facility',capacity: 6,  contact_pref: ['phone'] },
  blood_unit:          { code: 'blood_unit',          name: 'Blood Bank Dispatch',                            short: 'BLD',  agency_codes: ['blood_bank'],                                                 category: 'medical_blood',   capacity: 50, contact_pref: ['phone'] },
  // Fire / utilities
  fire_aerial:         { code: 'fire_aerial',         name: 'Fire Aerial Platform',                           short: 'FAP',  agency_codes: ['state_fire'],                                                 category: 'rescue_fire',     capacity: 4,  contact_pref: ['radio'] },
  fire_rescue_team:    { code: 'fire_rescue_team',    name: 'Fire Rescue Team (Cobra)',                       short: 'FRT',  agency_codes: ['state_fire'],                                                 category: 'rescue_collapse', capacity: 8,  contact_pref: ['radio'] },
  power_crew:          { code: 'power_crew',          name: 'DISCOM Restoration Crew',                        short: 'PWR',  agency_codes: ['state_discom','power_op'],                                    category: 'power',           capacity: 8,  contact_pref: ['phone'] },
  water_tanker:        { code: 'water_tanker',        name: 'Water Tanker',                                   short: 'TKR',  agency_codes: ['water_op','state_water'],                                     category: 'water_sanitation',capacity: 10000, contact_pref: ['phone'] },
  ro_unit:             { code: 'ro_unit',             name: 'Mobile RO Plant',                                short: 'RO',   agency_codes: ['water_op'],                                                   category: 'water_sanitation',capacity: 5000,  contact_pref: ['phone'] },
  // Comms / forecasting
  comms_cow:            { code: 'comms_cow',            name: 'Cell-on-Wheels (COW)',                          short: 'COW',  agency_codes: ['telecom_op'],                                                 category: 'comms',           capacity: 0,  contact_pref: ['phone'] },
  satellite_imagery:    { code: 'satellite_imagery',    name: 'Satellite Imagery Tasking',                     short: 'SAT',  agency_codes: ['isro'],                                                       category: 'forecasting',     capacity: 0,  contact_pref: ['data'] },
  forecast_cell:        { code: 'forecast_cell',        name: 'Forecast Cell (IMD/CWC/INCOIS)',                short: 'FCAST',agency_codes: ['imd','cwc','incois'],                                          category: 'forecasting',     capacity: 0,  contact_pref: ['data'] },
  // Transport / logistics
  bus_evac:            { code: 'bus_evac',            name: 'Mass-Evacuation Bus',                            short: 'BUS',  agency_codes: ['state_transport'],                                            category: 'evac_transport',  capacity: 60, contact_pref: ['phone'] },
  relief_train:        { code: 'relief_train',        name: 'Relief Train',                                   short: 'TRN',  agency_codes: ['railways'],                                                   category: 'evac_transport',  capacity: 1000, contact_pref: ['phone'] },
  truck_relief:        { code: 'truck_relief',        name: 'Relief Supply Truck',                            short: 'TRK',  agency_codes: ['ngo_relief','ircs','state_transport'],                        category: 'logistics',       capacity: 5000, contact_pref: ['phone'] },
  // Shelter / camps
  relief_camp:         { code: 'relief_camp',         name: 'Relief Camp',                                    short: 'CAMP', agency_codes: ['ddma','municipal','panchayat','ircs'],                        category: 'shelter',         capacity: 500, contact_pref: ['phone'] },
  // Volunteer
  ircs_team:           { code: 'ircs_team',           name: 'Red Cross Team',                                 short: 'IRC',  agency_codes: ['ircs'],                                                       category: 'civil',           capacity: 12, contact_pref: ['phone'] },
  civil_defence_unit:  { code: 'civil_defence_unit',  name: 'Civil Defence Unit',                             short: 'CD',   agency_codes: ['civil_defence'],                                              category: 'civil',           capacity: 12, contact_pref: ['phone'] },
  ncc_squad:           { code: 'ncc_squad',           name: 'NCC Cadet Squad',                                short: 'NCC',  agency_codes: ['ncc'],                                                        category: 'civil',           capacity: 20, contact_pref: ['phone'] },
  nss_squad:           { code: 'nss_squad',           name: 'NSS Volunteer Squad',                            short: 'NSS',  agency_codes: ['nss'],                                                        category: 'civil',           capacity: 20, contact_pref: ['phone'] },
  aapda_mitra_squad:   { code: 'aapda_mitra_squad',   name: 'Aapda Mitra Squad',                              short: 'AM',   agency_codes: ['aapda_mitra'],                                                category: 'civil',           capacity: 12, contact_pref: ['phone'] },
  scouts_team:         { code: 'scouts_team',         name: 'Bharat Scouts and Guides Team',                  short: 'BSG',  agency_codes: ['scouts_guides'],                                              category: 'civil',           capacity: 20, contact_pref: ['phone'] }
});

// ---------- Incident type → recommended unit categories ----------
//
// Used by the DSS to short-list candidate unit types when a triage
// returns a given incident_type. The dispatcher can override.
export const INCIDENT_PLAYBOOK = Object.freeze({
  flood:             ['rescue_water','medical_pre','medical_field','evac_transport','shelter','comms','water_sanitation','logistics'],
  landslide:         ['rescue_collapse','rescue_general','rescue_high_alt','medical_pre','engineering','logistics','forecasting'],
  earthquake:        ['rescue_collapse','rescue_general','medical_field','medical_facility','engineering','comms','shelter','power','water_sanitation','logistics'],
  fire:              ['rescue_fire','rescue_collapse','medical_pre','medical_field','security','engineering','logistics'],
  building_collapse: ['rescue_collapse','rescue_general','medical_pre','medical_field','engineering','security','logistics'],
  cyclone:           ['rescue_water','rescue_air','rescue_general','medical_pre','evac_transport','comms','power','water_sanitation','shelter','forecasting','logistics'],
  tsunami:           ['rescue_water','rescue_air','medical_pre','evac_transport','comms','shelter','forecasting','logistics'],
  industrial:        ['rescue_fire','rescue_general','medical_field','security','engineering','comms','logistics'],
  cbrn:              ['rescue_general','medical_field','medical_facility','security_armed','engineering','comms','forecasting','logistics'],
  unknown:           ['rescue_general','medical_pre','security','comms','logistics']
});

// ---------- Inter-agency mutual-aid edges ----------
//
// `from -> to[]` means `from` can task or formally request `to`. The
// graph is directed: NDMA can task NDRF; NDRF reports back to NDMA but
// is not authorised to task NDMA. Dispatchers use this for the "request
// support" affordance on a dispatch.
export const INTER_AGENCY = Object.freeze({
  ndma:           ['ndrf','sdma','mha_ndm','mod','imd','cwc','isro','incois','gsi','ircs'],
  pmo:            ['ndma','mod','mha','mha_ndm'],
  mha_ndm:        ['ndrf','crpf','bsf','itbp','ssb','cisf','assam_rifles','sdma'],
  ndrf:           ['sdrf','sdma','ddma','state_eoc','district_eoc'],
  mod:            ['army','navy','iaf','coast_guard'],
  army:           ['ndma','sdma','ddma','state_eoc'],
  navy:           ['ndma','sdma','ddma','state_eoc','coast_guard'],
  iaf:            ['ndma','sdma','ddma','state_eoc'],
  coast_guard:    ['ndma','sdma','ddma','navy','state_police'],
  sdma:           ['sdrf','state_police','state_fire','state_health','state_pwd','state_discom','state_water','state_transport','state_forest','ddma','state_eoc'],
  sdrf:           ['ddma','district_eoc','district_police'],
  state_eoc:      ['sdrf','state_police','state_fire','state_health','district_eoc'],
  state_police:   ['district_police','sdrf','state_fire'],
  state_fire:     ['district_police','sdrf'],
  state_health:   ['district_health','hospital_state','hospital_district','blood_bank','ambulance_service'],
  ddma:           ['district_police','district_health','district_eoc','sdm','bdo','tehsildar','municipal','panchayat','fire_station','hospital_district','hospital_chc','ambulance_service','civil_defence','aapda_mitra'],
  district_eoc:   ['fire_station','police_station','hospital_district','ambulance_service','civil_defence'],
  district_police: ['police_station'],
  district_health: ['hospital_district','hospital_chc','hospital_phc','ambulance_service','blood_bank'],
  sdm:            ['bdo','tehsildar','panchayat','ward_office','patwari'],
  bdo:            ['panchayat','aapda_mitra'],
  tehsildar:      ['patwari'],
  municipal:      ['ward_office','fire_station'],
  panchayat:      ['ward_office','aapda_mitra'],
  ircs:           ['ngo_relief','aapda_mitra','civil_defence'],
  civil_defence:  ['aapda_mitra'],
  aapda_mitra:    [],
  ncc:            ['nss','scouts_guides'],
  imd:            ['ndma','sdma','state_eoc','district_eoc'],
  cwc:            ['ndma','sdma','state_eoc','district_eoc'],
  incois:         ['ndma','sdma','coast_guard','navy'],
  gsi:            ['ndma','sdma','itbp','sdrf'],
  isro:           ['ndma','sdma','imd','cwc','gsi','incois']
});

// ---------- Helpers ----------

export function getAgency(code) {
  return AGENCIES[code] || null;
}
export function getUnitType(code) {
  return UNIT_TYPES[code] || null;
}
export function unitsForCategory(cat) {
  const out = [];
  for (const [code, t] of Object.entries(UNIT_TYPES)) {
    if (t.category === cat) out.push(code);
  }
  return out;
}
export function unitsForIncident(incident) {
  const cats = INCIDENT_PLAYBOOK[incident] || INCIDENT_PLAYBOOK.unknown;
  const out = new Set();
  for (const c of cats) for (const u of unitsForCategory(c)) out.add(u);
  return Array.from(out);
}
export function canTask(fromAgency, toAgency) {
  const out = INTER_AGENCY[fromAgency];
  return Array.isArray(out) && out.includes(toAgency);
}
export function ancestorAgencies(agencyCode) {
  const path = [];
  let cur = AGENCIES[agencyCode];
  while (cur) {
    path.push(cur.code);
    cur = cur.parent ? AGENCIES[cur.parent] : null;
  }
  return path;
}
export function isContactable(agencyCode) {
  const a = AGENCIES[agencyCode];
  return !!(a && a.contactable);
}

// Validators (for incoming unit-create payloads).
export function isValidUnitTypeCode(code) {
  return typeof code === 'string' && Object.prototype.hasOwnProperty.call(UNIT_TYPES, code);
}
export function isValidAgencyCode(code) {
  return typeof code === 'string' && Object.prototype.hasOwnProperty.call(AGENCIES, code);
}
export function isValidUnitCategory(cat) {
  return typeof cat === 'string' && Object.prototype.hasOwnProperty.call(UNIT_CATEGORIES, cat);
}
