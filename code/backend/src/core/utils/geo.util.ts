import * as geoip from 'geoip-lite';

/**
 * Returns the geographical location (City, Country) based on the IP address.
 * If the IP cannot be resolved (e.g., localhost), it returns null or 'Unknown Location'.
 * 
 * @param ip The IP address to look up
 * @returns string like "Hanoi, VN" or null if not found
 */
export function getLocationFromIp(ip: string | undefined): string | null {
  if (!ip) return null;

  // Handle localhost/private IPs that geoip-lite might not resolve
  if (ip === '127.0.0.1' || ip === '::1' || ip.startsWith('192.168.')) {
    return 'Local Network';
  }

  const geo = geoip.lookup(ip);
  
  if (geo) {
    const city = geo.city || 'Unknown City';
    const country = geo.country || 'Unknown Country';
    return `${city}, ${country}`;
  }

  return null;
}
