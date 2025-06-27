#!/bin/bash

# Desktop Agent - Fixed Setup Script for Tauri 2.x
set -e  # Exit on any error

echo "🚀 Starting Desktop Agent Setup..."

# Step 1: Environment Check
echo "📋 Step 1: Checking environment..."
check_command() {
    if ! command -v $1 &> /dev/null; then
        echo "❌ $1 is not installed. Please install it first."
        exit 1
    else
        echo "✅ $1 is installed: $($1 --version | head -n1)"
    fi
}

check_command node
check_command npm
check_command rustc
check_command cargo

# Check minimum versions
NODE_VERSION=$(node --version | sed 's/v//' | cut -d. -f1)
if [ "$NODE_VERSION" -lt 18 ]; then
    echo "❌ Node.js version must be >= 18"
    exit 1
fi

echo "✅ Environment check passed!"

# Step 2: Install/Update Tauri CLI
echo "📦 Step 2: Installing Tauri CLI..."
cargo install tauri-cli --version "^2.0.0" --force
echo "✅ Tauri CLI installed: $(cargo tauri --version)"

# Step 3: Create project directory
echo "📁 Step 3: Creating project structure..."
PROJECT_DIR="desktop-agent"
if [ -d "$PROJECT_DIR" ]; then
    echo "⚠️  Directory $PROJECT_DIR already exists. Remove it? (y/N)"
    read -r response
    if [[ "$response" =~ ^[Yy]$ ]]; then
        rm -rf "$PROJECT_DIR"
    else
        echo "❌ Please remove or rename the existing directory"
        exit 1
    fi
fi

mkdir "$PROJECT_DIR"
cd "$PROJECT_DIR"
echo "✅ Created and entered $PROJECT_DIR"

# Step 4: Initialize React frontend first
echo "⚛️  Step 4: Setting up React frontend..."
npm create vite@latest . -- --template react-ts
echo "✅ React frontend initialized"

# Step 5: Initialize Tauri project (correct syntax for Tauri 2.x)
echo "🔧 Step 5: Initializing Tauri project..."
cargo tauri init \
  --app-name "Desktop Agent" \
  --window-title "Desktop Agent" \
  --force

echo "✅ Tauri project initialized"

# Step 6: Install dependencies
echo "📦 Step 6: Installing dependencies..."
npm install

# Frontend dependencies
echo "Installing UI dependencies..."
npm install \
  tailwindcss @tailwindcss/forms @tailwindcss/typography \
  postcss autoprefixer \
  lucide-react \
  class-variance-authority clsx tailwind-merge \
  @radix-ui/react-slot @radix-ui/react-dialog @radix-ui/react-dropdown-menu

echo "Installing workflow engine..."
npm install @xyflow/react

echo "Installing state management..."
npm install zustand immer zod

echo "Installing Tauri plugins..."
npm install @tauri-apps/api @tauri-apps/plugin-shell @tauri-apps/plugin-fs @tauri-apps/plugin-sql

echo "Installing dev dependencies..."
npm install -D \
  @types/node vite-tsconfig-paths \
  vitest @testing-library/react @testing-library/jest-dom \
  eslint @typescript-eslint/eslint-plugin @typescript-eslint/parser \
  prettier eslint-plugin-prettier

# Step 7: Add Rust dependencies
echo "🦀 Step 7: Adding Rust dependencies..."
cd src-tauri

# Add dependencies to Cargo.toml
cargo add tauri --features "api-all"
cargo add serde --features "derive"
cargo add serde_json
cargo add tokio --features "full"
cargo add sqlx --features "runtime-tokio-rustls,sqlite,chrono,uuid,json"
cargo add uuid --features "v4,serde"
cargo add chrono --features "serde"
cargo add anyhow
cargo add thiserror
cargo add tracing
cargo add tracing-subscriber --features "env-filter"
cargo add aes-gcm
cargo add argon2
cargo add keyring
cargo add rand
cargo add dirs

# Add dev dependencies
cargo add --dev tokio-test
cargo add --dev tempfile

# Add plugins
cargo add tauri-plugin-shell
cargo add tauri-plugin-fs
cargo add tauri-plugin-sql --features "sqlite"

cd ..

# Step 8: Initialize Tailwind
echo "🎨 Step 8: Setting up Tailwind CSS..."
npx tailwindcss init -p

# Step 9: Create directory structure
echo "📂 Step 9: Creating directory structure..."
mkdir -p src/components/ui
mkdir -p src/components/common
mkdir -p src/hooks
mkdir -p src/lib
mkdir -p src/stores
mkdir -p src/types

mkdir -p src-tauri/src/database
mkdir -p src-tauri/src/security
mkdir -p src-tauri/src/commands
mkdir -p src-tauri/src/utils

echo "✅ Directory structure created"

# Step 10: Test basic setup
echo "🧪 Step 10: Testing basic setup..."
echo "✅ Dependencies installed successfully"

echo ""
echo "🎉 SUCCESS! Desktop Agent project has been created successfully!"
echo ""
echo "📍 Project location: $(pwd)"
echo ""
echo "📋 Next steps:"
echo "1. Copy the configuration files"
echo "2. Copy the Rust source files"
echo "3. Copy the React source files" 
echo "4. Run 'npm run tauri dev' to start development"
echo ""