// SPDX-License-Identifier: GPL-2.0
// Copyright (C) 2026 Objective Development Software GmbH
// Copyright (C) 2026 Ahoj Mail, ahoj.email
module.exports = function(grunt) {
    grunt.initConfig({
        svgstore: {
            options: {
                prefix: '',
                svg: {
                    "xmlns:xlink": "http://www.w3.org/1999/xlink",
                    xmlns: 'http://www.w3.org/2000/svg'
                }
            },
            default: {
                files: {
                    'webroot/sprite/generated-sprite.svg': ['webroot/svgs/*.svg'],
                },
            },
        },
    });
    grunt.loadNpmTasks('grunt-svgstore');
    grunt.registerTask('default', ['svgstore']);
};