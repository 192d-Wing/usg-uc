import { type ReactNode } from 'react';
import Alert from '@cloudscape-design/components/alert';
import Box from '@cloudscape-design/components/box';
import Button from '@cloudscape-design/components/button';
import Form from '@cloudscape-design/components/form';
import Modal from '@cloudscape-design/components/modal';
import SpaceBetween from '@cloudscape-design/components/space-between';

// FormModal — generic create/edit modal. Pages pass the FormField children;
// this component owns the modal chrome, the submit/cancel buttons, the
// loading state, and the error banner. Keeps every entity page short.
export function FormModal({
  visible,
  title,
  submitLabel,
  busy,
  error,
  onCancel,
  onSubmit,
  children,
}: Readonly<{
  visible: boolean;
  title: string;
  submitLabel?: string;
  busy?: boolean;
  error?: string | null;
  onCancel: () => void;
  onSubmit: () => void;
  children: ReactNode;
}>) {
  return (
    <Modal
      visible={visible}
      onDismiss={onCancel}
      header={title}
      size="medium"
      footer={
        <Box float="right">
          <SpaceBetween direction="horizontal" size="xs">
            <Button variant="link" onClick={onCancel} disabled={busy}>
              Cancel
            </Button>
            <Button variant="primary" onClick={onSubmit} loading={busy}>
              {submitLabel ?? 'Save'}
            </Button>
          </SpaceBetween>
        </Box>
      }
    >
      <Form errorText={error ?? undefined}>
        <SpaceBetween size="m">{children}</SpaceBetween>
      </Form>
    </Modal>
  );
}

// DeleteConfirmModal — single-resource delete confirmation. Surfaces the
// resource name so the operator knows what they're nuking.
export function DeleteConfirmModal({
  visible,
  resource,
  name,
  busy,
  error,
  onCancel,
  onConfirm,
}: Readonly<{
  visible: boolean;
  resource: string;
  name: string;
  busy?: boolean;
  error?: string | null;
  onCancel: () => void;
  onConfirm: () => void;
}>) {
  return (
    <Modal
      visible={visible}
      onDismiss={onCancel}
      header={`Delete ${resource}?`}
      size="small"
      footer={
        <Box float="right">
          <SpaceBetween direction="horizontal" size="xs">
            <Button variant="link" onClick={onCancel} disabled={busy}>
              Cancel
            </Button>
            <Button variant="primary" onClick={onConfirm} loading={busy}>
              Delete
            </Button>
          </SpaceBetween>
        </Box>
      }
    >
      <SpaceBetween size="s">
        <Box variant="p">
          Permanently delete <b>{name}</b>? This cannot be undone.
        </Box>
        {error ? <Alert type="error">{error}</Alert> : null}
      </SpaceBetween>
    </Modal>
  );
}
