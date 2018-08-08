const BundleAnalyzerPlugin = require('webpack-bundle-analyzer').BundleAnalyzerPlugin;
const UglifyJSPlugin = require('uglifyjs-webpack-plugin');
const path = require('path');
const webpack = require('webpack');

const analyze = !!process.env.ANALYZE_ENV;
const env = process.env.NODE_ENV || 'development';

const webpackConfig = {
  devtool: 'source-map',

  name: 'client',
  target: 'web',

  entry: {
    app: path.resolve('src/main.js'),
  },

  devServer: {
    // contentBase: path.join(__dirname, "dist"),
    contentBase: './dist',
    port: 9000,
  },

  module: {
    rules: [{
      test: /\.(js|jsx)$/,
      exclude: /node_modules/,
      loader: 'babel-loader',
    },
    {
      test: /\.exec\.js$/,
      include: path.resolve('lib'),
      loader: 'script-loader',
    },

    ],
  },

  plugins: [
    new webpack.DefinePlugin({
      'process.env': {
        NODE_ENV: JSON.stringify(env),
      },
    }),
  ],

  output: {
    filename: '[name].js',
    path: path.resolve('dist/js'),
    publicPath: '/js/',
  },

  resolve: {
    modules: [
      path.resolve('src'),
      'node_modules',
    ],
    extensions: ['.js', '.jsx'],
  },
};

if (analyze) {
  webpackConfig.plugins.push(new BundleAnalyzerPlugin());
}

if (env === 'production') {
  webpackConfig.plugins.push(
    new webpack.optimize.ModuleConcatenationPlugin(),
    new UglifyJSPlugin(),
    new webpack.HashedModuleIdsPlugin(),
  );
}

module.exports = webpackConfig;
