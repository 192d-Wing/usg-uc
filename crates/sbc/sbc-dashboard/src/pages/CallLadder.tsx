import { PlaceholderPage } from '../components/PlaceholderPage';

export function CallLadder() {
  return (
    <PlaceholderPage
      title="Call Ladder"
      description="SIP message ladder diagram for a selected call. Backed by /api/v1/calls/{call_id}/ladder."
    />
  );
}
