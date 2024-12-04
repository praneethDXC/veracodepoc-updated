package com.veracode.verademo.commands;
 
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
 
import org.apache.log4j.LogManager;
import org.apache.log4j.Logger;
 
public class IgnoreCommand implements BlabberCommand {
    private static final Logger logger = LogManager.getLogger("VeraDemo:IgnoreCommand");
 
    private Connection connect;
 
    private String username;
 
    public IgnoreCommand(Connection connect, String username) {
        super();
        this.connect = connect;
        this.username = username;
    }
 
    @Override
    public void execute(String blabberUsername) {
        String sqlQuery = "DELETE FROM listeners WHERE blabber=? AND listener=?;";
        logger.info(sqlQuery);
        PreparedStatement action;
        try {
            action = connect.prepareStatement(sqlQuery);
 
            action.setString(1, blabberUsername);
            action.setString(2, username);
            action.execute();
 
            sqlQuery = "SELECT blab_name FROM users WHERE username = ?";
            PreparedStatement sqlStatement = connect.prepareStatement(sqlQuery);
            sqlStatement.setString(1, blabberUsername);
            logger.info(sqlQuery);
            ResultSet result = sqlStatement.executeQuery();
            result.next();
 
            String event = username + " is now ignoring " + blabberUsername + " (" + result.getString(1) + ")";
            sqlQuery = "INSERT INTO users_history (blabber, event) VALUES (?, ?)";
            PreparedStatement insertStatement = connect.prepareStatement(sqlQuery);
            insertStatement.setString(1, username);
            insertStatement.setString(2, event);
            logger.info(sqlQuery);
            insertStatement.execute();
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }
}