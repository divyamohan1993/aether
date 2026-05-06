// Worker-summary localisation. The dispatcher pipeline writes a short
// status string back to the survivor on every worker_status change.
// English remains the source of truth; this module renders the same
// string in 14 additional Indian languages so a Malayalam, Telugu, or
// Assamese survivor can read what the system tells them.
//
// Strings are short, plain, and dignified. Lines tagged
// `// review-needed` are rendered in conservative, neutral phrasing
// pending a final pass by a native speaker before NDMA pilot.
//
// Banned-word and em-dash policy applies to every string here.

export const SUPPORTED_LOCALES = Object.freeze([
  'en', 'hi', 'ta', 'bn', 'ml', 'te', 'mr', 'or',
  'gu', 'pa', 'kn', 'ur', 'as', 'ne', 'mai'
]);

const SUPPORTED = new Set(SUPPORTED_LOCALES);

// ISO 639-3 (and a few common alternates) mapped to the 2-letter codes
// the system uses. Vertex's language_detected often emits 3-letter
// codes; the SOS PWA's Navigator-derived hint emits 2-letter or
// BCP-47 (e.g. ml-IN). Both must resolve cleanly.
const ALIAS = Object.freeze({
  eng: 'en', en: 'en',
  hin: 'hi', hi: 'hi',
  tam: 'ta', ta: 'ta',
  ben: 'bn', bn: 'bn', ban: 'bn',
  mal: 'ml', ml: 'ml',
  tel: 'te', te: 'te',
  mar: 'mr', mr: 'mr',
  ori: 'or', ory: 'or', or: 'or',
  guj: 'gu', gu: 'gu',
  pan: 'pa', pnb: 'pa', pa: 'pa',
  kan: 'kn', kn: 'kn',
  urd: 'ur', ur: 'ur',
  asm: 'as', as: 'as',
  nep: 'ne', ne: 'ne',
  mai: 'mai', mait: 'mai'
});

function normaliseTag(input) {
  if (typeof input !== 'string') return null;
  const cleaned = input.trim().toLowerCase();
  if (!cleaned) return null;
  // Strip BCP-47 region/script subtags, keep the primary language.
  const primary = cleaned.split(/[-_]/)[0];
  if (!primary) return null;
  if (SUPPORTED.has(primary)) return primary;
  if (ALIAS[primary]) return ALIAS[primary];
  if (ALIAS[cleaned]) return ALIAS[cleaned];
  return null;
}

// pickLocale(triageLangDetected, callerLangHint) -> supported 2-letter
// code. triage.language_detected wins because Vertex is more reliable
// than the survivor's browser locale; the caller hint is the fallback;
// 'en' is the final fallback. Unknown tags are ignored, never echoed.
export function pickLocale(triageLangDetected, callerLangHint) {
  const fromTriage = normaliseTag(triageLangDetected);
  if (fromTriage) return fromTriage;
  const fromHint = normaliseTag(callerLangHint);
  if (fromHint) return fromHint;
  return 'en';
}

const TEMPLATES = Object.freeze({
  en: {
    sm_received: 'Request received. Dispatcher reviewing now.',
    sm_under_review: 'Dispatcher is matching the right responders to your case.',
    sm_resources_assigned: 'Resources are being arranged. Hold on.',
    sm_dispatched: '{unit_name} dispatched.',
    sm_en_route: '{unit_name} en route.',
    sm_on_scene: '{unit_name} on scene.',
    sm_eta: 'ETA {minutes} minutes.',
    sm_call: 'Call {phone}.',
    sm_more_resources: '+{n} more resources tasked.',
    sm_resolved: 'Responders have closed this case. Stay safe.',
    sm_cancelled: 'Request cancelled. If you still need help, raise a fresh SOS.'
  },
  hi: {
    sm_received: 'अनुरोध मिल गया. नियंत्रक देख रहे हैं.',
    sm_under_review: 'नियंत्रक सही दल चुन रहे हैं.',
    sm_resources_assigned: 'मदद का इंतज़ाम हो रहा है. रुकिए.',
    sm_dispatched: '{unit_name} रवाना.',
    sm_en_route: '{unit_name} रास्ते में.',
    sm_on_scene: '{unit_name} पहुँच गए.',
    sm_eta: 'ETA {minutes} मिनट.',
    sm_call: 'फ़ोन करें {phone}.',
    sm_more_resources: '+{n} और संसाधन लगे.',
    sm_resolved: 'मामला बंद किया गया. सुरक्षित रहें.',
    sm_cancelled: 'अनुरोध रद्द. अब भी मदद चाहिए तो नया SOS भेजें.'
  },
  ta: {
    sm_received: 'கோரிக்கை கிடைத்தது. அலுவலர் பார்க்கிறார்.',
    sm_under_review: 'அலுவலர் சரியான குழுவைத் தேர்வு செய்கிறார்.',
    sm_resources_assigned: 'உதவி ஏற்பாடாகிறது. காத்திருங்கள்.',
    sm_dispatched: '{unit_name} அனுப்பப்பட்டது.',
    sm_en_route: '{unit_name} வழியில்.',
    sm_on_scene: '{unit_name} இடத்தில்.',
    sm_eta: 'ETA {minutes} நிமிடம்.',
    sm_call: '{phone} ஐ அழைக்கவும்.',
    sm_more_resources: '+{n} கூடுதல் வளங்கள்.',
    sm_resolved: 'வழக்கு முடிந்தது. பாதுகாப்பாக இருங்கள்.',
    sm_cancelled: 'கோரிக்கை ரத்து. மீண்டும் தேவை எனில் புதிய SOS அனுப்பவும்.'
  },
  bn: {
    sm_received: 'অনুরোধ এসেছে. কর্মী দেখছেন.',
    sm_under_review: 'কর্মী সঠিক দল বেছে নিচ্ছেন.',
    sm_resources_assigned: 'সাহায্যের ব্যবস্থা হচ্ছে. অপেক্ষা করুন.',
    sm_dispatched: '{unit_name} রওনা হলো.',
    sm_en_route: '{unit_name} পথে আছে.',
    sm_on_scene: '{unit_name} ঘটনাস্থলে.',
    sm_eta: 'ETA {minutes} মিনিট.',
    sm_call: '{phone} নম্বরে ফোন করুন.',
    sm_more_resources: '+{n} আরও সাহায্য পাঠানো হলো.',
    sm_resolved: 'সাহায্যকারীরা কেস বন্ধ করেছেন. নিরাপদে থাকুন.',
    sm_cancelled: 'অনুরোধ বাতিল. এখনো সাহায্য দরকার হলে নতুন SOS পাঠান.'
  },
  ml: {
    sm_received: 'അഭ്യർത്ഥന കിട്ടി. ഉദ്യോഗസ്ഥൻ പരിശോധിക്കുന്നു.',
    sm_under_review: 'ഉദ്യോഗസ്ഥൻ ശരിയായ സംഘത്തെ തിരഞ്ഞെടുക്കുന്നു.',
    sm_resources_assigned: 'സഹായം ഒരുക്കുന്നു. കാത്തിരിക്കൂ.',
    sm_dispatched: '{unit_name} അയച്ചു.',
    sm_en_route: '{unit_name} വഴിയിൽ.',
    sm_on_scene: '{unit_name} സ്ഥലത്ത്.',
    sm_eta: 'ETA {minutes} മിനിറ്റ്.',
    sm_call: '{phone} ലേക്ക് വിളിക്കൂ.',
    sm_more_resources: '+{n} കൂടുതൽ വിഭവങ്ങൾ വിന്യസിച്ചു.',
    sm_resolved: 'സഹായികൾ കേസ് അടച്ചു. സുരക്ഷിതരായിരിക്കൂ.',
    sm_cancelled: 'അഭ്യർത്ഥന റദ്ദാക്കി. ഇപ്പോഴും സഹായം വേണമെങ്കിൽ പുതിയ SOS അയക്കൂ.'
  },
  te: {
    sm_received: 'అభ్యర్థన అందింది. అధికారి చూస్తున్నారు.',
    sm_under_review: 'అధికారి సరైన బృందాన్ని ఎంచుకుంటున్నారు.',
    sm_resources_assigned: 'సహాయం సిద్ధం చేస్తున్నారు. ఉండండి.',
    sm_dispatched: '{unit_name} బయలుదేరింది.',
    sm_en_route: '{unit_name} దారిలో ఉంది.',
    sm_on_scene: '{unit_name} స్థలంలో ఉంది.',
    sm_eta: 'ETA {minutes} నిమిషాలు.',
    sm_call: '{phone} కు కాల్ చేయండి.',
    sm_more_resources: '+{n} మరిన్ని వనరులు పంపబడ్డాయి.',
    sm_resolved: 'సహాయకులు కేసును ముగించారు. క్షేమంగా ఉండండి.',
    sm_cancelled: 'అభ్యర్థన రద్దు. ఇప్పటికీ సహాయం కావాలంటే కొత్త SOS పంపండి.'
  },
  mr: {
    sm_received: 'विनंती मिळाली. अधिकारी पाहत आहेत.',
    sm_under_review: 'अधिकारी योग्य पथक निवडत आहेत.',
    sm_resources_assigned: 'मदतीची सोय होत आहे. थांबा.',
    sm_dispatched: '{unit_name} रवाना झाली.',
    sm_en_route: '{unit_name} मार्गावर.',
    sm_on_scene: '{unit_name} ठिकाणी पोहोचली.',
    sm_eta: 'ETA {minutes} मिनिटे.',
    sm_call: '{phone} वर फोन करा.',
    sm_more_resources: '+{n} अधिक साधने पाठवली.',
    sm_resolved: 'बचाव दलाने प्रकरण बंद केले. सुरक्षित रहा.',
    sm_cancelled: 'विनंती रद्द. अजून मदत हवी असल्यास नवीन SOS पाठवा.'
  },
  or: {
    sm_received: 'ଅନୁରୋଧ ମିଳିଲା. ଅଧିକାରୀ ଦେଖୁଛନ୍ତି.',
    sm_under_review: 'ଅଧିକାରୀ ଠିକ୍ ଦଳ ବାଛୁଛନ୍ତି.',
    sm_resources_assigned: 'ସାହାଯ୍ୟର ବ୍ୟବସ୍ଥା ହେଉଛି. ଅପେକ୍ଷା କରନ୍ତୁ.',
    sm_dispatched: '{unit_name} ବାହାରିଲା.',
    sm_en_route: '{unit_name} ବାଟରେ ଅଛି.',
    sm_on_scene: '{unit_name} ସ୍ଥାନରେ ପହଞ୍ଚିଲା.',
    sm_eta: 'ETA {minutes} ମିନିଟ୍.',
    sm_call: '{phone} କୁ ଫୋନ୍ କରନ୍ତୁ.',
    sm_more_resources: '+{n} ଅଧିକ ସମ୍ବଳ ପଠାଗଲା.',
    sm_resolved: 'ସାହାଯ୍ୟକାରୀ କେସ୍ ବନ୍ଦ କଲେ. ସୁରକ୍ଷିତ ରୁହନ୍ତୁ.',
    sm_cancelled: 'ଅନୁରୋଧ ବାତିଲ୍. ଏବେ ବି ସାହାଯ୍ୟ ଲୋଡ଼ିଲେ ନୂଆ SOS ପଠାନ୍ତୁ.'
  },
  gu: {
    sm_received: 'વિનંતી મળી. અધિકારી જોઈ રહ્યા છે.',
    sm_under_review: 'અધિકારી યોગ્ય ટીમ પસંદ કરી રહ્યા છે.',
    sm_resources_assigned: 'મદદની વ્યવસ્થા થઈ રહી છે. થોભો.',
    sm_dispatched: '{unit_name} રવાના થઈ.',
    sm_en_route: '{unit_name} રસ્તે છે.',
    sm_on_scene: '{unit_name} સ્થળે પહોંચી.',
    sm_eta: 'ETA {minutes} મિનિટ.',
    sm_call: '{phone} પર ફોન કરો.',
    sm_more_resources: '+{n} વધુ સાધનો મોકલ્યા.',
    sm_resolved: 'બચાવ દળે કેસ બંધ કર્યો. સુરક્ષિત રહો.',
    sm_cancelled: 'વિનંતી રદ. હજી મદદ જોઈએ તો નવો SOS મોકલો.'
  },
  pa: {
    sm_received: 'ਬੇਨਤੀ ਮਿਲ ਗਈ. ਅਫ਼ਸਰ ਵੇਖ ਰਹੇ ਹਨ.',
    sm_under_review: 'ਅਫ਼ਸਰ ਸਹੀ ਟੀਮ ਚੁਣ ਰਹੇ ਹਨ.',
    sm_resources_assigned: 'ਮਦਦ ਦਾ ਇੰਤਜ਼ਾਮ ਹੋ ਰਿਹਾ ਹੈ. ਠਹਿਰੋ.',
    sm_dispatched: '{unit_name} ਰਵਾਨਾ ਹੋਈ.',
    sm_en_route: '{unit_name} ਰਸਤੇ ਵਿੱਚ ਹੈ.',
    sm_on_scene: '{unit_name} ਥਾਂ ਉੱਤੇ ਹੈ.',
    sm_eta: 'ETA {minutes} ਮਿੰਟ.',
    sm_call: '{phone} ਉੱਤੇ ਫ਼ੋਨ ਕਰੋ.',
    sm_more_resources: '+{n} ਹੋਰ ਸਾਧਨ ਭੇਜੇ.',
    sm_resolved: 'ਬਚਾਅ ਦਲ ਨੇ ਕੇਸ ਬੰਦ ਕੀਤਾ. ਸੁਰੱਖਿਅਤ ਰਹੋ.',
    sm_cancelled: 'ਬੇਨਤੀ ਰੱਦ. ਹਾਲੇ ਵੀ ਮਦਦ ਚਾਹੀਦੀ ਹੈ ਤਾਂ ਨਵੀਂ SOS ਭੇਜੋ.'
  },
  kn: {
    sm_received: 'ವಿನಂತಿ ಸಿಕ್ಕಿತು. ಅಧಿಕಾರಿ ನೋಡುತ್ತಿದ್ದಾರೆ.',
    sm_under_review: 'ಅಧಿಕಾರಿ ಸರಿಯಾದ ತಂಡ ಆಯ್ಕೆ ಮಾಡುತ್ತಿದ್ದಾರೆ.',
    sm_resources_assigned: 'ಸಹಾಯ ಸಿದ್ಧವಾಗುತ್ತಿದೆ. ಕಾಯಿರಿ.',
    sm_dispatched: '{unit_name} ಹೊರಟಿತು.',
    sm_en_route: '{unit_name} ದಾರಿಯಲ್ಲಿ.',
    sm_on_scene: '{unit_name} ಸ್ಥಳದಲ್ಲಿ.',
    sm_eta: 'ETA {minutes} ನಿಮಿಷಗಳು.',
    sm_call: '{phone} ಗೆ ಕರೆ ಮಾಡಿ.',
    sm_more_resources: '+{n} ಇನ್ನೂ ಸಂಪನ್ಮೂಲ ಕಳುಹಿಸಲಾಗಿದೆ.',
    sm_resolved: 'ರಕ್ಷಕರು ಕೇಸ್ ಮುಚ್ಚಿದ್ದಾರೆ. ಸುರಕ್ಷಿತವಾಗಿರಿ.',
    sm_cancelled: 'ವಿನಂತಿ ರದ್ದು. ಇನ್ನೂ ಸಹಾಯ ಬೇಕಿದ್ದರೆ ಹೊಸ SOS ಕಳುಹಿಸಿ.'
  },
  ur: {
    sm_received: 'درخواست مل گئی۔ افسر دیکھ رہے ہیں۔',
    sm_under_review: 'افسر صحیح ٹیم چن رہے ہیں۔',
    sm_resources_assigned: 'مدد کا انتظام ہو رہا ہے۔ رکیں۔',
    sm_dispatched: '{unit_name} روانہ۔',
    sm_en_route: '{unit_name} راستے میں۔',
    sm_on_scene: '{unit_name} موقع پر۔',
    sm_eta: 'ETA {minutes} منٹ۔',
    sm_call: '{phone} پر فون کریں۔',
    sm_more_resources: '+{n} مزید وسائل بھیجے گئے۔',
    sm_resolved: 'امدادی ٹیم نے کیس بند کر دیا۔ محفوظ رہیں۔',
    sm_cancelled: 'درخواست منسوخ۔ اب بھی مدد چاہیے تو نئی SOS بھیجیں۔'
  },
  as: {
    sm_received: 'অনুৰোধ পালোঁ. বিষয়াই চাই আছে.', // review-needed
    sm_under_review: 'বিষয়াই উপযুক্ত দল বাছি আছে.', // review-needed
    sm_resources_assigned: 'সহায়ৰ ব্যৱস্থা হৈ আছে. ৰখা.',
    sm_dispatched: '{unit_name} ৰাওনা হ’ল.',
    sm_en_route: '{unit_name} বাটত আছে.',
    sm_on_scene: '{unit_name} ঠাইত পালে.',
    sm_eta: 'ETA {minutes} মিনিট.',
    sm_call: '{phone} লৈ ফোন কৰক.',
    sm_more_resources: '+{n} আৰু সম্পদ পঠাইছে.',
    sm_resolved: 'উদ্ধাৰকাৰীয়ে কেছ বন্ধ কৰিলে. সুৰক্ষিত থাকক.', // review-needed
    sm_cancelled: 'অনুৰোধ বাতিল. এতিয়াও সহায় লাগিলে নতুন SOS পঠাওক.'
  },
  ne: {
    sm_received: 'अनुरोध आयो. अधिकारीले हेर्दैछन्.',
    sm_under_review: 'अधिकारीले सही टोली छान्दैछन्.',
    sm_resources_assigned: 'सहायताको प्रबन्ध हुँदैछ. कुर्नुहोस्.',
    sm_dispatched: '{unit_name} पठाइयो.',
    sm_en_route: '{unit_name} बाटोमा.',
    sm_on_scene: '{unit_name} स्थानमा.',
    sm_eta: 'ETA {minutes} मिनेट.',
    sm_call: '{phone} मा फोन गर्नुहोस्.',
    sm_more_resources: '+{n} थप स्रोत पठाइए.',
    sm_resolved: 'उद्धारकर्ताले केस बन्द गरे. सुरक्षित रहनुहोस्.',
    sm_cancelled: 'अनुरोध रद्द. अझै सहायता चाहिएमा नयाँ SOS पठाउनुहोस्.'
  },
  mai: {
    sm_received: 'अनुरोध भेटल. अधिकारी देख रहल छथि.', // review-needed
    sm_under_review: 'अधिकारी सही टोली चुन रहल छथि.', // review-needed
    sm_resources_assigned: 'मदति के व्यवस्था भ’ रहल अछि. ठहरू.', // review-needed
    sm_dispatched: '{unit_name} रवाना भेल.',
    sm_en_route: '{unit_name} रस्ता में.',
    sm_on_scene: '{unit_name} स्थान पर.',
    sm_eta: 'ETA {minutes} मिनट.',
    sm_call: '{phone} पर फोन करू.',
    sm_more_resources: '+{n} आओर संसाधन पठाओल गेल.',
    sm_resolved: 'राहत दल केस बन्द कएलनि. सुरक्षित रहू.', // review-needed
    sm_cancelled: 'अनुरोध रद्द. आओरो मदति चाही त’ नव SOS पठाऊ.' // review-needed
  }
});

// Substitute {var} with vars[var]; missing vars render as empty.
// Curly literals are not expected in templates.
function substitute(template, vars) {
  if (!vars || typeof vars !== 'object') return template;
  return template.replace(/\{([a-z_][a-z0-9_]*)\}/gi, (_m, key) => {
    const v = vars[key];
    return v === undefined || v === null ? '' : String(v);
  });
}

// t(localeCode, key, vars={}) renders the survivor-facing string. If
// the locale or the key is missing, we fall back to English so the
// caller never sees an empty string mid-emergency.
export function t(localeCode, key, vars = {}) {
  const code = SUPPORTED.has(localeCode) ? localeCode : 'en';
  const pack = TEMPLATES[code] || TEMPLATES.en;
  const tmpl = pack[key] !== undefined ? pack[key]
    : (TEMPLATES.en[key] !== undefined ? TEMPLATES.en[key] : '');
  return substitute(tmpl, vars);
}

export const _internal = { TEMPLATES, normaliseTag };
