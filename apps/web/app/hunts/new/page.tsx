import { NewHuntForm } from "@/components/new-hunt-form";

export default function NewHuntPage() {
  return <><header className="page-head"><div><div className="eyebrow">Repository intake</div><h1>New hunt</h1><p className="subhead">Clone an authorised Solidity repository and run the local analysis pipeline.</p></div></header><NewHuntForm /></>;
}
