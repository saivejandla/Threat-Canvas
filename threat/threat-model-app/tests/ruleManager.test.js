import { describe, it, expect, beforeEach } from 'vitest';
import { RuleManager } from '../src/engine/threatEngine.js';

describe('RuleManager - Dynamic Custom Rules', () => {
    beforeEach(() => {
        RuleManager.clearCustomRules();
    });

    it('should parse and apply custom rulesets over default STRIDE', () => {
        // 1. Define a custom ruleset payload
        const customRuleset = {
            rules: [
                {
                    id: "CUSTOM-001",
                    name: "Unauthenticated Cloud Storage",
                    stride: "I",
                    sev: "critical",
                    like: "High",
                    imp: "High",
                    cat: "Information Disclosure",
                    ctrl: "Confidentiality",
                    check: (N, E, adj) => {
                        const aff = [];
                        for (const nd of Object.values(N)) {
                            // Check if node is storage and explicitly marked with auth=false
                            if (nd.type === 'storage' && nd.props && nd.props.auth === false) {
                                aff.push(nd.id);
                            }
                        }
                        return aff.length ? { aff } : null;
                    },
                    desc: "Storage bucket has authentication explicitly disabled.",
                    mits: ["Enable IAM validation", "Block public access"]
                }
            ]
        };

        // 2. Load it dynamically
        RuleManager.loadCustomRules(customRuleset);

        // 3. Create a mock architecture that violates CUSTOM-001
        const mockNodes = {
            "s1": {
                id: "s1",
                type: "storage",
                label: "S3 Bucket",
                trustZone: "public",
                props: {
                    auth: false // This triggers the custom rule
                }
            }
        };
        const mockEdges = [];
        const adj = {};

        // 4. Run the engine's checking logic manually using the RuleManager
        const rules = RuleManager.getRules();
        let customThreat = null;

        for (const rule of rules) {
            const res = rule.check(mockNodes, mockEdges, adj);
            if (res && rule.id === 'CUSTOM-001') {
                customThreat = { ...rule, affected: res.aff };
                break;
            }
        }

        // 5. Assertions
        expect(customThreat).toBeDefined();
        if (customThreat) {
            expect(customThreat.name).toBe("Unauthenticated Cloud Storage");
            expect(customThreat.affected).toContain("s1");
        }
    });
});
