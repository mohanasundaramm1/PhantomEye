"use client";

import React, { useEffect, useRef, useState, useMemo } from 'react';
import Globe from 'react-globe.gl';
import { scaleLinear } from 'd3-scale';

interface MapData {
    sample_country: string;
    risk_score: number;
    threat_count: number;
}

interface TacticalGlobeProps {
    data: MapData[];
}

export default function TacticalGlobe({ data }: TacticalGlobeProps) {
    const globeRef = useRef<any>(null);
    const [mounted, setMounted] = useState(false);

    // Custom Hook to load window size safely for Next.js SSR
    useEffect(() => {
        setMounted(true);
    }, []);

    // -- 1. Data Processing for Visualization --

    // Convert country names to lat/lng (simplified centroid map for major countries)
    // In a full prod app, we'd use a robust geo-centroid library or lat/lng from backend.
    // For this tactical view, we'll map key active regions manually to ensure visual fidelity.
    const countryCentroids: Record<string, { lat: number, lng: number, code: string }> = {
        "United States": { lat: 37.0902, lng: -95.7129, code: "US" },
        "China": { lat: 35.8617, lng: 104.1954, code: "CN" },
        "Russia": { lat: 61.5240, lng: 105.3188, code: "RU" },
        "Germany": { lat: 51.1657, lng: 10.4515, code: "DE" },
        "Brazil": { lat: -14.2350, lng: -51.9253, code: "BR" },
        "Australia": { lat: -25.2744, lng: 133.7751, code: "AU" },
        "India": { lat: 20.5937, lng: 78.9629, code: "IN" },
        "France": { lat: 46.2276, lng: 2.2137, code: "FR" },
        "United Kingdom": { lat: 55.3781, lng: -3.4360, code: "GB" },
        "Canada": { lat: 56.1304, lng: -106.3468, code: "CA" },
        "Netherlands": { lat: 52.1326, lng: 5.2913, code: "NL" },
        "The Netherlands": { lat: 52.1326, lng: 5.2913, code: "NL" },
        "Japan": { lat: 36.2048, lng: 138.2529, code: "JP" },
        "South Korea": { lat: 35.9078, lng: 127.7669, code: "KR" },
        "Iran": { lat: 32.4279, lng: 53.6880, code: "IR" },
        "North Korea": { lat: 40.3399, lng: 127.5101, code: "KP" },
        "Ukraine": { lat: 48.3794, lng: 31.1656, code: "UA" },
    };

    // Prepare Hex/Bar Data
    const hexData = useMemo(() => {
        return (data || []).map(d => {
            const coords = countryCentroids[d.sample_country] || countryCentroids["United States"]; // Fallback to US if unknown for now
            const weight = Number.isFinite(d.risk_score) ? d.risk_score : 0;
            return {
                lat: coords.lat,
                lng: coords.lng,
                weight,
                country: d.sample_country,
                color: weight > 0.9 ? "#ff0000" : weight > 0.7 ? "#ff8800" : "#00bcd4"
            };
        }).filter(d => Number.isFinite(d.lat) && Number.isFinite(d.lng));
    }, [data]);

    // NOTE: an earlier version drew animated 'attack arcs' between random
    // country pairs (Math.random() target selection) purely for visual effect.
    // They represented no real observed relationship between infrastructure,
    // which directly contradicted this dashboard's own 'no simulated events'
    // claim, so they were removed. Do not reintroduce decorative geometry here:
    // if arcs come back, they must encode a real edge (e.g. shared ASN, shared
    // registrar, or same-campaign cluster membership) sourced from the API.

    useEffect(() => {
        if (globeRef.current) {
            // Auto-rotation
            globeRef.current.controls().autoRotate = true;
            globeRef.current.controls().autoRotateSpeed = 0.5;
            globeRef.current.controls().enableZoom = false; // Keep usage simplified
        }
    }, [mounted]);

    // -- Render --
    if (!mounted) return <div className="w-full h-full flex items-center justify-center opacity-20 animate-pulse">INITIALIZING_HOLOGRAPHIC_PROJECTION...</div>;

    return (
        <div className='relative w-full h-full cursor-move'>
            <Globe
                ref={globeRef}
                backgroundColor="rgba(0,0,0,0)" // Transparent to blend with dashboard
                globeImageUrl="//unpkg.com/three-globe/example/img/earth-night.jpg"
                bumpImageUrl="//unpkg.com/three-globe/example/img/earth-topology.png"
                backgroundImageUrl="//unpkg.com/three-globe/example/img/night-sky.png"

                // Atmosphere
                atmosphereColor="#00bcd4" // Cyan atmosphere
                atmosphereAltitude={0.15}

                // Points/Bars
                hexBinPointsData={hexData}
                hexBinPointWeight="weight"
                hexAltitude={(d: any) => (d.points?.length ? d.sumWeight / d.points.length : 0) * 0.4} // Height based on mean risk in bin (d is a hexbin, not a point)
                hexBinResolution={4} // Chunky tech look
                hexTopColor={(d: any) => d.points[0].color}
                hexSideColor={() => "rgba(0, 50, 50, 0.6)"}
                hexBinMerge={true}


                width={800} // Fixed width to match container logic (will be responsive via container hidden overflow)
                height={600}
            />

            <div className='absolute bottom-4 right-4 pointer-events-none'>
                <div className='flex flex-col items-end gap-1 text-[8px] font-mono text-cyan-400 opacity-60'>
                    <span>RENDER: WEBGL_2.0</span>
                    <span>FPS: 60.0_LOCKED</span>
                    <span>TEXTURE: 8K_NIGHT_VIS</span>
                </div>
            </div>
        </div>
    );
}
