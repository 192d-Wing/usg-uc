import type { TabsProps } from '@cloudscape-design/components/tabs';

import type { ModelOption, Phone } from '../../lib/phoneModel';
import { IdentityTab } from './tabs/IdentityTab';
import { BlfTab, LineKeysTab, SoftkeysTab, SpeedDialsTab } from './tabs/KeysTabs';
import { LinesTab } from './tabs/LinesTab';
import {
  AudioTab,
  DirectoryTab,
  DisplayTab,
  EmergencyTab,
  FeaturesTab,
  NetworkTab,
  PagingTab,
} from './tabs/SettingsTabs';

type Ctx = Readonly<{
  form: Phone;
  onChange: (next: Phone) => void;
  model: ModelOption;
  genericName: string;
  onModelChange: (next: import('../../lib/phoneModel').ModelValue, genericName: string) => void;
  modelLocked: boolean;
}>;

const identityTab = (ctx: Ctx): TabsProps.Tab => ({
  id: 'identity',
  label: 'Identity',
  content: (
    <IdentityTab
      form={ctx.form}
      onChange={ctx.onChange}
      model={ctx.model}
      genericName={ctx.genericName}
      onModelChange={ctx.onModelChange}
      modelLocked={ctx.modelLocked}
    />
  ),
});

const linesTab = (ctx: Ctx, showCallForward = true): TabsProps.Tab => ({
  id: 'lines',
  label: 'Lines',
  content: (
    <LinesTab
      form={ctx.form}
      onChange={ctx.onChange}
      model={ctx.model}
      showCallForward={showCallForward}
    />
  ),
});

const blfTab = (ctx: Ctx): TabsProps.Tab => ({
  id: 'blf',
  label: 'BLF',
  content: <BlfTab form={ctx.form} onChange={ctx.onChange} />,
});

const speedDialsTab = (ctx: Ctx): TabsProps.Tab => ({
  id: 'speed-dials',
  label: 'Speed dials',
  content: <SpeedDialsTab form={ctx.form} onChange={ctx.onChange} />,
});

const softkeysTab = (ctx: Ctx): TabsProps.Tab => ({
  id: 'softkeys',
  label: 'Softkeys',
  content: <SoftkeysTab form={ctx.form} onChange={ctx.onChange} />,
});

const lineKeysTab = (ctx: Ctx): TabsProps.Tab => ({
  id: 'line-keys',
  label: 'Line keys',
  content: (
    <LineKeysTab form={ctx.form} onChange={ctx.onChange} limit={ctx.model.maxLines} />
  ),
});

const featuresTab = (ctx: Ctx): TabsProps.Tab => ({
  id: 'features',
  label: 'Features',
  content: <FeaturesTab form={ctx.form} onChange={ctx.onChange} />,
});

const networkTab = (ctx: Ctx): TabsProps.Tab => ({
  id: 'network',
  label: 'Network',
  content: <NetworkTab form={ctx.form} onChange={ctx.onChange} />,
});

const displayTab = (ctx: Ctx): TabsProps.Tab => ({
  id: 'display',
  label: 'Display',
  content: <DisplayTab form={ctx.form} onChange={ctx.onChange} />,
});

const audioTab = (ctx: Ctx): TabsProps.Tab => ({
  id: 'audio',
  label: 'Audio',
  content: <AudioTab form={ctx.form} onChange={ctx.onChange} />,
});

const directoryTab = (ctx: Ctx): TabsProps.Tab => ({
  id: 'directory',
  label: 'Directory',
  content: <DirectoryTab form={ctx.form} onChange={ctx.onChange} />,
});

const pagingTab = (ctx: Ctx): TabsProps.Tab => ({
  id: 'paging',
  label: 'Paging',
  content: <PagingTab form={ctx.form} onChange={ctx.onChange} />,
});

const emergencyTab = (ctx: Ctx): TabsProps.Tab => ({
  id: 'emergency',
  label: 'Emergency',
  content: <EmergencyTab form={ctx.form} onChange={ctx.onChange} />,
});

// Vendor → tab order. Tabs only appear if relevant to the family.
export function tabsForFamily(ctx: Ctx): TabsProps.Tab[] {
  const fam = ctx.model.family;
  switch (fam) {
    case 'polycom_vvx':
      return [
        identityTab(ctx),
        linesTab(ctx),
        blfTab(ctx),
        speedDialsTab(ctx),
        softkeysTab(ctx),
        featuresTab(ctx),
        networkTab(ctx),
        displayTab(ctx),
        audioTab(ctx),
        directoryTab(ctx),
        pagingTab(ctx),
        emergencyTab(ctx),
      ];
    case 'polycom_trio':
      return [
        identityTab(ctx),
        linesTab(ctx),
        speedDialsTab(ctx),
        featuresTab(ctx),
        networkTab(ctx),
        displayTab(ctx),
        audioTab(ctx),
        directoryTab(ctx),
        pagingTab(ctx),
        emergencyTab(ctx),
      ];
    case 'poly_edge':
      return [
        identityTab(ctx),
        linesTab(ctx),
        blfTab(ctx),
        speedDialsTab(ctx),
        softkeysTab(ctx),
        featuresTab(ctx),
        networkTab(ctx),
        displayTab(ctx),
        audioTab(ctx),
        directoryTab(ctx),
        pagingTab(ctx),
        emergencyTab(ctx),
      ];
    case 'cisco_mpp':
      return [
        identityTab(ctx),
        linesTab(ctx, true),
        speedDialsTab(ctx),
        softkeysTab(ctx),
        featuresTab(ctx),
        networkTab(ctx),
        displayTab(ctx),
        audioTab(ctx),
        directoryTab(ctx),
        pagingTab(ctx),
        emergencyTab(ctx),
      ];
    case 'cisco_9800':
      return [
        identityTab(ctx),
        linesTab(ctx, true),
        speedDialsTab(ctx),
        softkeysTab(ctx),
        featuresTab(ctx),
        networkTab(ctx),
        displayTab(ctx),
        audioTab(ctx),
        directoryTab(ctx),
        pagingTab(ctx),
        emergencyTab(ctx),
      ];
    case 'teo':
      return [
        identityTab(ctx),
        linesTab(ctx),
        lineKeysTab(ctx),
        featuresTab(ctx),
        networkTab(ctx),
        displayTab(ctx),
        emergencyTab(ctx),
      ];
    case 'generic':
    default:
      return [
        identityTab(ctx),
        linesTab(ctx),
        speedDialsTab(ctx),
        featuresTab(ctx),
        networkTab(ctx),
        displayTab(ctx),
        audioTab(ctx),
        directoryTab(ctx),
        pagingTab(ctx),
        emergencyTab(ctx),
      ];
  }
}
