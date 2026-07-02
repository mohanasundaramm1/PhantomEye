import React, { useRef, useEffect, useState } from 'react';
import ForceGraph2D from 'react-force-graph-2d';

interface NetworkGraphProps {
  data: {
    nodes: any[];
    links: any[];
  }
}

export default function NetworkGraph({ data }: NetworkGraphProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const [dimensions, setDimensions] = useState({ width: 800, height: 600 });
  const graphRef = useRef<any>(null);

  useEffect(() => {
    if (containerRef.current) {
      setDimensions({
        width: containerRef.current.clientWidth,
        height: containerRef.current.clientHeight
      });
    }
    
    const handleResize = () => {
      if (containerRef.current) {
        setDimensions({
          width: containerRef.current.clientWidth,
          height: containerRef.current.clientHeight
        });
      }
    };
    
    window.addEventListener('resize', handleResize);
    return () => window.removeEventListener('resize', handleResize);
  }, []);

  return (
    <div ref={containerRef} className="w-full h-full relative cursor-crosshair">
      <div className="absolute top-2 left-2 flex gap-4 text-[9px] font-black uppercase tracking-widest z-10">
        <div className="flex items-center gap-1"><div className="w-2 h-2 bg-tactical-red"></div>Domain</div>
        <div className="flex items-center gap-1"><div className="w-2 h-2 bg-cyan-400"></div>ASN</div>
        <div className="flex items-center gap-1"><div className="w-2 h-2 bg-orange-500"></div>TLD</div>
      </div>
      {data && data.nodes && data.nodes.length > 0 ? (
        <ForceGraph2D
          ref={graphRef}
          width={dimensions.width}
          height={dimensions.height}
          graphData={data}
          nodeColor={node => {
            if (node.group === 'domain') return '#ff0000';
            if (node.group === 'asn') return '#00ffff';
            if (node.group === 'tld') return '#ff8800';
            return '#ffffff';
          }}
          nodeRelSize={4}
          linkColor={() => 'rgba(255, 255, 255, 0.1)'}
          linkWidth={link => link.value ? (link.value as number) * 2 : 1}
          linkDirectionalParticles={2}
          linkDirectionalParticleWidth={1.5}
          linkDirectionalParticleSpeed={0.01}
          backgroundColor="transparent"
          onNodeClick={(node) => {
            // center on node horizontally and vertically
            graphRef.current.centerAt(node.x, node.y, 1000);
            graphRef.current.zoom(8, 2000);
          }}
          nodeCanvasObject={(node: any, ctx, globalScale) => {
            const label = node.label;
            const fontSize = 12/globalScale;
            ctx.font = `bold ${fontSize}px monospace`;
            ctx.textAlign = 'center';
            ctx.textBaseline = 'middle';
            
            // Draw Node
            ctx.beginPath();
            ctx.arc(node.x, node.y, 4, 0, 2 * Math.PI, false);
            ctx.fillStyle = node.group === 'domain' ? '#ff0000' : node.group === 'asn' ? '#00ffff' : '#ff8800';
            ctx.fill();
            
            // Draw Text
            if (globalScale >= 2) {
              ctx.fillText(label, node.x, node.y + 8);
              ctx.fillStyle = '#fff';
            }
          }}
        />
      ) : (
        <div className="w-full h-full flex items-center justify-center opacity-20 italic">
          SYNCING_NETWORK_TOPOLOGY...
        </div>
      )}
    </div>
  );
}
