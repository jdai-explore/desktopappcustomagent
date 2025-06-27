// test-security.js - Add this to your browser dev tools console when app is running

async function testSecuritySystem() {
    console.log("🔒 Testing Security System...");
    
    try {
        // Test 1: Health check
        console.log("1️⃣ Testing security health check...");
        const healthResult = await window.__TAURI__.core.invoke('test_security_system');
        console.log("✅ Security health check:", healthResult);
        
        // Test 2: Store API key
        console.log("2️⃣ Testing API key storage...");
        const storeResult = await window.__TAURI__.core.invoke('store_api_key', {
            provider: 'test_provider',
            apiKey: 'test-api-key-12345'
        });
        console.log("✅ Store API key result:", storeResult);
        
        // Test 3: Retrieve API key
        console.log("3️⃣ Testing API key retrieval...");
        const retrievedKey = await window.__TAURI__.core.invoke('get_api_key', {
            provider: 'test_provider'
        });
        console.log("✅ Retrieved API key:", retrievedKey);
        
        // Test 4: List providers
        console.log("4️⃣ Testing provider listing...");
        const providers = await window.__TAURI__.core.invoke('list_configured_providers');
        console.log("✅ Configured providers:", providers);
        
        // Test 5: Delete API key
        console.log("5️⃣ Testing API key deletion...");
        const deleteResult = await window.__TAURI__.core.invoke('delete_api_key', {
            provider: 'test_provider'
        });
        console.log("✅ Delete API key result:", deleteResult);
        
        // Test 6: Verify deletion
        console.log("6️⃣ Verifying deletion...");
        const retrievedAfterDelete = await window.__TAURI__.core.invoke('get_api_key', {
            provider: 'test_provider'
        });
        console.log("✅ API key after deletion:", retrievedAfterDelete);
        
        // Test 7: General health check
        console.log("7️⃣ Testing general health check...");
        const generalHealth = await window.__TAURI__.core.invoke('health_check');
        console.log("✅ General health:", generalHealth);
        
        console.log("🎉 All security tests completed successfully!");
        return true;
        
    } catch (error) {
        console.error("❌ Security test failed:", error);
        return false;
    }
}

// Run the test
testSecuritySystem();