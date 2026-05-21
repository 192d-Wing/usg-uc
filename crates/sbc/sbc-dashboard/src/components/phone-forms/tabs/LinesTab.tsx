import Box from '@cloudscape-design/components/box';
import SpaceBetween from '@cloudscape-design/components/space-between';

import type { ModelOption, Phone } from '../../../lib/phoneModel';
import { LinesEditor } from '../editors/LinesEditor';

export function LinesTab({
  form,
  onChange,
  model,
  showCallForward = true,
}: Readonly<{
  form: Phone;
  onChange: (next: Phone) => void;
  model: ModelOption;
  showCallForward?: boolean;
}>) {
  return (
    <SpaceBetween size="m">
      <Box color="text-status-info" variant="small">
        {model.label} supports up to {model.maxLines} line{model.maxLines === 1 ? '' : 's'}.
      </Box>
      <LinesEditor
        items={form.lines}
        onChange={(lines) => onChange({ ...form, lines })}
        limit={model.maxLines}
        showCallForward={showCallForward}
      />
    </SpaceBetween>
  );
}
