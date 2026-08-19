/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,

  // The MTProto layer uses Web Crypto and BigInt, both of which need a real
  // browser. Nothing here renders on the server, so the crypto never runs in
  // Node.
  env: {
    NEXT_PUBLIC_API_URL: process.env.NEXT_PUBLIC_API_URL ?? "https://api.example.com",
    NEXT_PUBLIC_WS_URL: process.env.NEXT_PUBLIC_WS_URL ?? "wss://api.example.com/mtproto",
  },

  async headers() {
    return [
      {
        source: "/:path*",
        headers: [
          // The client holds an auth key in memory. A content injection would
          // be able to read it, so the CSP is strict.
          {
            key: "Content-Security-Policy",
            value: [
              "default-src 'self'",
              "script-src 'self' 'unsafe-inline'",
              "style-src 'self' 'unsafe-inline'",
              "img-src 'self' data: https:",
              "connect-src 'self' https: wss:",
              "frame-ancestors 'none'",
              "base-uri 'self'",
              "form-action 'self'",
            ].join("; "),
          },
          { key: "X-Content-Type-Options", value: "nosniff" },
          { key: "X-Frame-Options", value: "DENY" },
          { key: "Referrer-Policy", value: "strict-origin-when-cross-origin" },
          { key: "Strict-Transport-Security", value: "max-age=63072000; includeSubDomains; preload" },
        ],
      },
    ];
  },
};

export default nextConfig;
