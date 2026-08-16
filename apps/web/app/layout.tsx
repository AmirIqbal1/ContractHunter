import type { Metadata } from "next";
import Link from "next/link";
import "./globals.css";

export const metadata: Metadata = { title: "ContractHunter", description: "Local smart-contract security analysis workstation" };

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return <html lang="en"><body><div className="shell">
    <aside className="sidebar">
      <Link href="/" className="brand"><span className="brand-mark">C</span><span>ContractHunter</span></Link>
      <nav className="nav"><Link href="/">Overview</Link><Link href="/hunts/new">New Hunt</Link><Link href="/hypotheses">Hypotheses</Link><Link href="/investigations">Investigations</Link><Link href="/invariants">Invariants</Link><Link href="/findings">Raw Findings</Link></nav>
      <div className="system"><span className="online" />Local system online<br /><span style={{ marginLeft: 14 }}>V0.1.8 / Local verification</span></div>
    </aside>
    <main className="main">{children}</main>
  </div></body></html>;
}
