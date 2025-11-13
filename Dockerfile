# Use official Node.js LTS image
FROM node:18-alpine

# Set working directory
WORKDIR /usr/src/app


# Copy package files
COPY package*.json ./

# Copy all source code and config files
COPY . .

# Install all dependencies (including devDependencies)
RUN npm install

# Build TypeScript
RUN npm run build

# Remove devDependencies for a smaller image (optional)
RUN npm prune --production

# Expose port (change if your app uses a different port)
EXPOSE 8080

# Start the app
CMD ["npm", "start"]
