import Link from "next/link";

export default function NotFound() { return <div className="card form-card"><div className="eyebrow">404 / Not found</div><h1>Record not found</h1><p className="subhead" style={{ marginBottom: 24 }}>The requested hunt or finding does not exist.</p><Link className="button" href="/">RETURN TO OVERVIEW</Link></div>; }
