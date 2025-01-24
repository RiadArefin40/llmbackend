'use strict';

/** @type {import('sequelize-cli').Migration} */
module.exports = {
  async up (queryInterface, Sequelize) {
    /**
     * Add altering commands here.
     *
     * Example:
     * await queryInterface.createTable('users', { id: Sequelize.INTEGER });
     */
  },

  async down (queryInterface, Sequelize) {
    /**
     * Add reverting commands here.
     *
     * Example:
     * await queryInterface.dropTable('users');
     */
  },
  up: async (queryInterface, Sequelize) => {
    // Add a new column "role" to the "users" table
    await queryInterface.addColumn('users', 'role', {
      type: Sequelize.STRING,
      allowNull: false,
      defaultValue: 'user', // Default value for role
    });
  },

  down: async (queryInterface, Sequelize) => {
    // Remove the "role" column if rolling back the migration
    await queryInterface.removeColumn('users', 'role');
  },
};
