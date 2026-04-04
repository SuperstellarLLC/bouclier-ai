import { Page, Stack, Heading, Text, Button, Divider } from "@n3rd-ai/ui";

export default function NotFound() {
  return (
    <Page>
      <Stack gap="xl" align="center" style={{ paddingTop: "8rem", paddingBottom: "4rem" }}>
        <Heading level={1} gradient>
          404
        </Heading>
        <Text size="lg" color="secondary">
          What you&apos;re looking for doesn&apos;t exist, sailor.
        </Text>
        <Divider variant="dashed" />
        <Button variant="primary" href="/">
          Back to shore
        </Button>
      </Stack>
    </Page>
  );
}
