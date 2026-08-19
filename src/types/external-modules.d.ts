declare module 'cors' {
  import type { RequestHandler } from 'express';
  const cors: (options?: Record<string, unknown>) => RequestHandler;
  export default cors;
}

declare module 'whois-json' {
  const whois: (target: string, options?: Record<string, unknown>) => Promise<Record<string, unknown>>;
  export default whois;
}
