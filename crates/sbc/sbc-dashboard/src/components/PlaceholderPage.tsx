import Box from '@cloudscape-design/components/box';
import ContentLayout from '@cloudscape-design/components/content-layout';
import Header from '@cloudscape-design/components/header';
import Container from '@cloudscape-design/components/container';
import StatusIndicator from '@cloudscape-design/components/status-indicator';

// Used for routes whose Angular counterparts haven't been ported yet.
// Keeps navigation working end-to-end so the operator can see the menu and
// click around without 404s during the migration.
export function PlaceholderPage({
  title,
  description,
}: Readonly<{
  title: string;
  description?: string;
}>) {
  return (
    <ContentLayout header={<Header variant="h1">{title}</Header>}>
      <Container header={<Header variant="h2">Migration in progress</Header>}>
        <Box>
          <StatusIndicator type="in-progress">Not yet ported to Cloudscape</StatusIndicator>
          {description ? (
            <Box variant="p" padding={{ top: 's' }}>
              {description}
            </Box>
          ) : null}
        </Box>
      </Container>
    </ContentLayout>
  );
}
