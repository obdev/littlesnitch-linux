// SPDX-License-Identifier: GPL-2.0
// Copyright (C) 2026 Objective Development Software GmbH
// Copyright (C) 2026 Ahoj Mail, ahoj.email

const path = require('path');

// Extracts and minifies sass files.
const MiniCssExtractPlugin = require("mini-css-extract-plugin");

const RemoveEmptyScriptsPlugin = require('webpack-remove-empty-scripts');

// Minifies js files.
const TerserPlugin = require("terser-webpack-plugin");

// Minifies the outputted CSS files, it was needed when imported css files inside sass file, which wasn't getting minified.
const CssMinimizerPlugin = require("css-minimizer-webpack-plugin");

module.exports = {
    optimization: {
        minimize: true,
        removeAvailableModules: false,
        removeEmptyChunks: false,
        splitChunks: false,
        minimizer: [
            new CssMinimizerPlugin(), new TerserPlugin()
        ],
    },
    plugins: [
        new MiniCssExtractPlugin({
            filename: './webroot/css/[name].min.css',
            chunkFilename: 'webroot/css/[name].chunk.css'
        }),
        new RemoveEmptyScriptsPlugin(),
    ],
    mode: 'production',
    module: {
        rules: [
            {
                test: /.s?css$/,
                use: [
                    MiniCssExtractPlugin.loader,
                    {
                        loader: 'css-loader',
                        options: {sourceMap: true}
                    },
                    {
                        loader: 'resolve-url-loader',
                        options: {sourceMap: true}
                    },
                    {
                        loader: 'sass-loader',
                        options: {sourceMap: true}
                    }
                ]
            }, {
                test: /\.(ttf|eot|woff|woff2|svg)$/,
                type: 'asset/resource',
                generator: {
                    emit: false,
                    filename: "./webroot/fonts/[name][ext]",
                },
            }
        ],
    },
    watch: true,
    watchOptions: {
        poll: 500,
        //aggregateTimeout: 5000,
        ignored: ['/node_modules/', '**/node_modules'],
        stdin: true,
    },
    // Entry files to be built along with it's output path.
    entry: {
        style: {
            import: './webroot/css/app.scss',
        },
        header: {
            import: './webroot/js/header-app.js',
            filename: './webroot/js/[name]-app.min.js'
        },
        footer: {
            import: './webroot/js/footer-app.js',
            filename: './webroot/js/[name]-app.min.js'
        }
    },
    output: {
        pathinfo: false,
        path: path.resolve(__dirname, ''),
    },
};