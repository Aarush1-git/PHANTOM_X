import React from 'react';
import { PageHeader } from '../components/common/PageHeader';
import { PlaygroundWorkspace } from '../components/playground/PlaygroundWorkspace';

export const PlaygroundPage: React.FC = () => {
  return (
    <div className="space-y-6">
      <PageHeader
        title="PHANTOM Playground"
        description="Interactive, controlled security testing sandbox. Explore attack scenarios, review non-destructive execution plans, authorize simulations, and inspect verified evidence."
      />

      <PlaygroundWorkspace />
    </div>
  );
};
