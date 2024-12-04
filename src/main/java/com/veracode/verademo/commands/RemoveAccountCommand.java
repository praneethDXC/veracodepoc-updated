package com.veracode.verademo.commands;
 
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
 
import org.apache.log4j.LogManager;
import org.apache.log4j.Logger;
 
public class RemoveAccountCommand implements BlabberCommand {
    private static final Logger logger = LogManager.getLogger("VeraDemo:RemoveAccountCommand");
 
    private Connection connect;
 
    public RemoveAccountCommand(Connection connect, String username) {
        super();
        this.connect = connect;
    }
 
    @Override
    public void execute(String blabberUsername) {
        String sqlQuery = "DELETE FROM listeners WHERE blabber=? OR listener=?;";
        logger.info(sqlQuery);
        PreparedStatement action;
        try {
            action = connect.prepareStatement(sqlQuery);
 
            action.setString(1, blabberUsername);
            action.setString(2, blabberUsername);
            action.execute();
 
            sqlQuery = "SELECT blab_name FROM users WHERE username = ?";
            PreparedStatement sqlStatement = connect.prepareStatement(sqlQuery);
            sqlStatement.setString(1, blabberUsername);
            logger.info(sqlQuery);
            ResultSet result = sqlStatement.executeQuery();
            result.next();
 
            String event = "Removed account for blabber " + result.getString(1);
            sqlQuery = "INSERT INTO users_history (blabber, event) VALUES (?, ?)";
            logger.info(sqlQuery);
            PreparedStatement insertStatement = connect.prepareStatement(sqlQuery);
            insertStatement.setString(1, blabberUsername);
            insertStatement.setString(2, event);
            insertStatement.execute();
 
            sqlQuery = "DELETE FROM users WHERE username = ?";
            logger.info(sqlQuery);
            PreparedStatement deleteStatement = connect.prepareStatement(sqlQuery);
            deleteStatement.setString(1, blabberUsername);
            deleteStatement.execute();
 
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }
}
 