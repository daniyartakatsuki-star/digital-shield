const cache = new Map();
const pending = new Map();

function firstUrl(text, kind) {
  const match = text.match(/(?:https?:\/\/|www\.)[^\s<>"']+/i);
  let candidate = kind === 'link' ? text.trim() : match?.[0]?.replace(/[.,!;:]+$/, '');
  if (!candidate) return null;
  if (kind !== 'link' && candidate.endsWith(')') && !candidate.includes('(')) candidate = candidate.slice(0,-1);
  if (!/^[a-z][\w+.-]*:/i.test(candidate)) candidate = 'https://' + candidate;
  try {
    const url = new URL(candidate);
    if (!['http:', 'https:'].includes(url.protocol) || !url.hostname.includes('.') || url.username || url.password || /\s/.test(candidate)) return null;
    url.hash = '';
    return url.href;
  } catch { return null; }
}

async function fetchReport(url, key, request) {
  const id = Buffer.from(url).toString('base64url');
  try {
    const response = await request('https://www.virustotal.com/api/v3/urls/' + id, {
      headers: {'x-apikey': key}, redirect: 'error', signal: AbortSignal.timeout(10000)
    });
    if (!response.ok) {
      const notices = {401:'VirusTotal не принял ключ проекта.',403:'У ключа проекта нет доступа к этому отчёту.',404:'В базе VirusTotal пока нет отчёта по этому адресу. Это не значит, что сайт безопасен — часто мошеннические сайты совсем новые.',429:'Закончилась квота запросов VirusTotal. Попробуйте через минуту.'};
      return {url,notice:notices[response.status] || 'VirusTotal временно недоступен.'};
    }
    const {data} = await response.json();
    const attributes = data?.attributes;
    const stats = attributes?.last_analysis_stats;
    if (!stats || !Object.values(stats).length || !Object.values(stats).every(n => Number.isSafeInteger(n) && n >= 0)) return {url,notice:'VirusTotal не вернул результаты антивирусов.'};
    const vendors = Object.entries(attributes.last_analysis_results || {}).map(([name,entry]) => ({name,category:entry?.category || 'unreported',result:entry?.result || ''}));
    vendors.sort((a,b) => Number(['malicious','suspicious'].includes(b.category))-Number(['malicious','suspicious'].includes(a.category)) || a.name.localeCompare(b.name));
    const report = {url,stats,vendors,date:attributes.last_analysis_date || null,link:/^[a-f0-9]{64}$/i.test(data.id || '') ? 'https://www.virustotal.com/gui/url/'+data.id : null};
    if(cache.size>=100)cache.delete(cache.keys().next().value);
    cache.set(url,{report,expires:Date.now()+300000});
    return report;
  } catch { return {url,notice:'Не удалось получить отчёт VirusTotal. Проверьте подключение и попробуйте ещё раз.'}; }
}

export async function lookup(text,kind,key,request=fetch) {
  const url=firstUrl(text,kind);
  if(!url)return kind==='link' ? {notice:'Введите адрес сайта, например https://example.com, чтобы найти отчёт.'} : {notice:'В тексте нет ссылки — VirusTotal проверяет только ссылки.'};
  if(!key)return {url,notice:'Ключ VirusTotal не настроен, поэтому отчёт по ссылке не загружен.'};
  const saved=cache.get(url);
  if(saved?.expires>Date.now())return saved.report;
  if(!pending.has(url)) pending.set(url,fetchReport(url,key,request).finally(()=>pending.delete(url)));
  return pending.get(url);
}
